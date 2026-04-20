#!/usr/bin/env python3
"""
Terminal-only IP scanner.

- No web UI
- No port binding
- Scans all IPs from ip.json
- Targets 5000 worker threads
- Uses a 3 second request timeout
- Saves matching IPs into the found directory
- Prints smart live progress and a final found-IP summary
"""

import ipaddress
import json
import os
import signal
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

import psutil

try:
    from curl_cffi import requests as curl_requests
    CURL_CFFI_AVAILABLE = True
except ImportError:
    import requests as curl_requests
    CURL_CFFI_AVAILABLE = False
    print("[!] Warning: curl_cffi not available, falling back to requests.")

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


def _read_positive_int_env(name: str) -> Optional[int]:
    raw_value = os.getenv(name)
    if not raw_value:
        return None

    try:
        value = int(raw_value)
    except ValueError:
        print(f"[!] Ignoring invalid {name}={raw_value!r} (expected integer)")
        return None

    if value <= 0:
        print(f"[!] Ignoring invalid {name}={raw_value!r} (must be > 0)")
        return None

    return value


def _read_positive_float_env(name: str) -> Optional[float]:
    raw_value = os.getenv(name)
    if not raw_value:
        return None

    try:
        value = float(raw_value)
    except ValueError:
        print(f"[!] Ignoring invalid {name}={raw_value!r} (expected number)")
        return None

    if value <= 0:
        print(f"[!] Ignoring invalid {name}={raw_value!r} (must be > 0)")
        return None

    return value


TARGET_ERROR = "Internal server error: Request method 'GET' is not supported"
FOUND_DIR = Path("found")
IP_JSON_FILE = Path("ip.json")
DEFAULT_WORKERS = _read_positive_int_env("SCANNER_TERMINAL_WORKERS") or 6000
REQUEST_TIMEOUT = _read_positive_float_env("SCANNER_TERMINAL_TIMEOUT") or 5.0
RETRYABLE_RETRIES = _read_positive_int_env("SCANNER_TERMINAL_RETRYABLE_RETRIES")
if RETRYABLE_RETRIES is None:
    RETRYABLE_RETRIES = 2
RETRY_BACKOFF_SECONDS = _read_positive_float_env("SCANNER_TERMINAL_RETRY_BACKOFF_SECONDS") or 0.25
RETRY_BACKOFF_MAX_SECONDS = _read_positive_float_env("SCANNER_TERMINAL_RETRY_BACKOFF_MAX_SECONDS") or 1.0
LIMIT_IPS = _read_positive_int_env("SCANNER_TERMINAL_LIMIT")
DRY_RUN = os.getenv("SCANNER_TERMINAL_DRY_RUN") == "1"

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
}

SCAN_FOUND = "found"
SCAN_NOT_FOUND = "not_found"
SCAN_TIMEOUT = "timeout"
SCAN_OTHER_ERROR = "other_error"

FOUND_DIR.mkdir(exist_ok=True)
stats_lock = threading.Lock()
found_lock = threading.Lock()
stop_event = threading.Event()
scan_done_event = threading.Event()


@dataclass
class ScanStats:
    total: int = 0
    processed: int = 0
    found: int = 0
    not_found: int = 0
    timeout_errors: int = 0
    other_errors: int = 0
    in_flight: int = 0
    requested_workers: int = 0
    started_workers: int = 0
    start_time: float = 0.0
    found_ips: List[str] = field(default_factory=list)


stats = ScanStats()


class ConsoleRenderer:
    def __init__(self):
        self._lock = threading.Lock()
        self._last_len = 0

    def update_status(self, text: str) -> None:
        with self._lock:
            width = max(self._last_len, len(text))
            sys.stdout.write("\r" + text.ljust(width))
            sys.stdout.flush()
            self._last_len = width

    def log(self, text: str = "") -> None:
        with self._lock:
            if self._last_len:
                sys.stdout.write("\r" + (" " * self._last_len) + "\r")
            sys.stdout.write(text + "\n")
            sys.stdout.flush()
            self._last_len = 0

    def finish(self) -> None:
        with self._lock:
            if self._last_len:
                sys.stdout.write("\n")
                sys.stdout.flush()
                self._last_len = 0


renderer = ConsoleRenderer()


def get_retry_delay_seconds(attempt_index: int) -> float:
    retry_number = max(attempt_index + 1, 1)
    delay = RETRY_BACKOFF_SECONDS * retry_number
    return min(delay, RETRY_BACKOFF_MAX_SECONDS)


def format_duration(seconds: float) -> str:
    if seconds <= 0:
        return "0s"

    whole_seconds = int(seconds)
    hours, remainder = divmod(whole_seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def expand_cidr(cidr: str) -> Iterator[str]:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        prefix = network.prefixlen

        if prefix < 8:
            renderer.log(f"[!] Skipping {cidr} - extremely large network ({network.num_addresses:,} IPs)")
            return

        if prefix < 16:
            num_ips = network.num_addresses - 2
            renderer.log(f"[*] Expanding large CIDR {cidr} -> {num_ips:,} IPs")

        for ip in network.hosts():
            yield str(ip)
    except ValueError as exc:
        renderer.log(f"[!] Invalid CIDR {cidr}: {exc}")


def load_ips_from_json(filepath: Path) -> List[str]:
    renderer.log(f"[*] Loading IPs from {filepath}...")

    with open(filepath, "r", encoding="utf-8") as file_handle:
        data = json.load(file_handle)

    unique_ips: List[str] = []
    seen_ips = set()
    prefixes: List[str] = []

    if isinstance(data, dict) and "prefixes" in data:
        for prefix in data["prefixes"]:
            if isinstance(prefix, dict) and "ip_prefix" in prefix:
                prefixes.append(prefix["ip_prefix"])
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                if "/" in item:
                    prefixes.append(item)
                elif item not in seen_ips:
                    seen_ips.add(item)
                    unique_ips.append(item)
            elif isinstance(item, dict):
                if "ip_prefix" in item:
                    prefixes.append(item["ip_prefix"])
                elif "ip" in item:
                    ip = item["ip"]
                    if ip not in seen_ips:
                        seen_ips.add(ip)
                        unique_ips.append(ip)

    renderer.log(f"[*] Found {len(prefixes):,} CIDR prefixes")

    total_estimate = 0
    for cidr in prefixes:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if network.prefixlen >= 8:
                total_estimate += network.num_addresses - 2
        except ValueError:
            continue

    renderer.log(f"[*] Estimated IPs to generate: {total_estimate:,}")
    renderer.log("[*] Expanding CIDR prefixes...")

    for index, cidr in enumerate(prefixes):
        if index % 50 == 0 or index == len(prefixes) - 1:
            renderer.log(
                f"    Prefix progress: {index + 1:,}/{len(prefixes):,} "
                f"({len(unique_ips):,} unique IPs so far)"
            )

        for ip in expand_cidr(cidr):
            if ip not in seen_ips:
                seen_ips.add(ip)
                unique_ips.append(ip)

    if LIMIT_IPS is not None and LIMIT_IPS < len(unique_ips):
        renderer.log(f"[*] Limiting scan to first {LIMIT_IPS:,} IPs because SCANNER_TERMINAL_LIMIT is set")
        unique_ips = unique_ips[:LIMIT_IPS]

    renderer.log(f"[*] Total unique IPs ready: {len(unique_ips):,}")
    return unique_ips


def snapshot_stats() -> ScanStats:
    with stats_lock:
        return ScanStats(
            total=stats.total,
            processed=stats.processed,
            found=stats.found,
            not_found=stats.not_found,
            timeout_errors=stats.timeout_errors,
            other_errors=stats.other_errors,
            in_flight=stats.in_flight,
            requested_workers=stats.requested_workers,
            started_workers=stats.started_workers,
            start_time=stats.start_time,
            found_ips=list(stats.found_ips),
        )


def apply_scan_deltas(
    *,
    processed: int = 0,
    found: int = 0,
    not_found: int = 0,
    timeout_errors: int = 0,
    other_errors: int = 0,
    found_ips: Optional[List[str]] = None,
) -> None:
    with stats_lock:
        stats.processed += processed
        stats.found += found
        stats.not_found += not_found
        stats.timeout_errors += timeout_errors
        stats.other_errors += other_errors
        if found_ips:
            stats.found_ips.extend(found_ips)


def note_request_started() -> None:
    with stats_lock:
        stats.in_flight += 1


def note_request_finished() -> None:
    with stats_lock:
        if stats.in_flight > 0:
            stats.in_flight -= 1


def build_progress_line() -> str:
    snap = snapshot_stats()
    elapsed = max(time.time() - snap.start_time, 0.001)
    rate = snap.processed / elapsed if elapsed > 0 else 0.0
    remaining = max(snap.total - snap.processed, 0)
    eta_seconds = remaining / rate if rate > 0 else 0.0
    progress = (snap.processed / snap.total * 100.0) if snap.total else 0.0

    return (
        f"[*] Progress {snap.processed:,}/{snap.total:,} ({progress:5.1f}%) | "
        f"Found {snap.found:,} | "
        f"Timeouts-invalid {snap.timeout_errors:,} | "
        f"Other {snap.other_errors:,} | "
        f"Rate {rate:,.0f}/s | "
        f"ETA {format_duration(eta_seconds)} | "
        f"In-flight {snap.in_flight:,} | "
        f"Threads {snap.started_workers:,}/{snap.requested_workers:,}"
    )


def progress_reporter() -> None:
    while not scan_done_event.is_set():
        renderer.update_status(build_progress_line())
        scan_done_event.wait(timeout=1.0)

    renderer.update_status(build_progress_line())
    renderer.finish()


class IPScanner:
    def __init__(self):
        self._thread_local = threading.local()

    def get_session(self):
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = curl_requests.Session()
            self._thread_local.session = session
        return session

    def reset_session(self) -> None:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            return

        with suppress(Exception):
            session.close()
        self._thread_local.session = None

    @staticmethod
    def get_request_headers() -> dict:
        return {**DEFAULT_HEADERS, "Host": "api.ivacbd.com"}

    @staticmethod
    def build_result(ip: str, response, response_text: str) -> dict:
        return {
            "ip": ip,
            "status_code": response.status_code,
            "response": response_text,
            "headers": dict(response.headers),
            "timestamp": datetime.now().isoformat(),
        }

    def scan_ip(self, ip: str) -> Tuple[str, Optional[dict]]:
        url = f"https://{ip}/iams/api/v1/slots/reserveSlot"
        headers = self.get_request_headers()

        for attempt in range(RETRYABLE_RETRIES + 1):
            note_request_started()
            try:
                session = self.get_session()
                if CURL_CFFI_AVAILABLE:
                    response = session.get(
                        url,
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                        verify=False,
                        impersonate="chrome110",
                        allow_redirects=False,
                    )
                else:
                    response = session.get(
                        url,
                        headers=headers,
                        timeout=REQUEST_TIMEOUT,
                        verify=False,
                        allow_redirects=False,
                    )

                response_text = response.text
                if TARGET_ERROR in response_text:
                    return SCAN_FOUND, self.build_result(ip, response, response_text)
                return SCAN_NOT_FOUND, None
            except curl_requests.exceptions.Timeout:
                return SCAN_TIMEOUT, None
            except curl_requests.exceptions.ConnectionError:
                pass
            except curl_requests.exceptions.RequestException:
                pass
            except Exception:
                pass
            finally:
                note_request_finished()

            self.reset_session()
            if attempt >= RETRYABLE_RETRIES:
                return SCAN_OTHER_ERROR, None

            time.sleep(get_retry_delay_seconds(attempt))

        return SCAN_OTHER_ERROR, None

    @staticmethod
    def save_found(result: dict) -> None:
        ip = result["ip"]
        safe_ip = ip.replace(".", "_")
        filepath = FOUND_DIR / f"{safe_ip}.txt"

        with found_lock:
            with open(filepath, "w", encoding="utf-8") as file_handle:
                file_handle.write(f"IP: {ip}\n")
                file_handle.write(f"Timestamp: {result['timestamp']}\n")
                file_handle.write(f"Status Code: {result['status_code']}\n")
                file_handle.write(f"Headers: {json.dumps(result['headers'], indent=2)}\n")
                file_handle.write(f"\n{'=' * 50}\n")
                file_handle.write(f"Response:\n{result['response']}\n")


scanner = IPScanner()


def threaded_worker(
    ip_list: List[str],
    index_state: dict,
    index_lock: threading.Lock,
    chunk_size: int,
) -> int:
    local_processed = 0
    local_found = 0
    local_not_found = 0
    local_timeout_errors = 0
    local_other_errors = 0
    local_found_ips: List[str] = []
    total_ips = len(ip_list)

    while not stop_event.is_set():
        with index_lock:
            start = index_state["next_index"]
            index_state["next_index"] += chunk_size

        if start >= total_ips:
            break

        end = min(start + chunk_size, total_ips)
        for ip in ip_list[start:end]:
            if stop_event.is_set():
                break

            try:
                outcome, result = scanner.scan_ip(ip)
                local_processed += 1

                if outcome == SCAN_FOUND and result is not None:
                    scanner.save_found(result)
                    local_found += 1
                    local_found_ips.append(result["ip"])
                    renderer.log(f"[FOUND] {result['ip']} saved to {FOUND_DIR}")
                elif outcome == SCAN_NOT_FOUND:
                    local_not_found += 1
                elif outcome == SCAN_TIMEOUT:
                    local_timeout_errors += 1
                else:
                    local_other_errors += 1
            except Exception as exc:
                local_processed += 1
                local_other_errors += 1
                renderer.log(f"[!] Worker error on {ip}: {exc}")

            if (
                local_processed >= 64
                or local_timeout_errors >= 16
                or local_other_errors >= 16
                or local_found
            ):
                apply_scan_deltas(
                    processed=local_processed,
                    found=local_found,
                    not_found=local_not_found,
                    timeout_errors=local_timeout_errors,
                    other_errors=local_other_errors,
                    found_ips=local_found_ips,
                )
                local_processed = 0
                local_found = 0
                local_not_found = 0
                local_timeout_errors = 0
                local_other_errors = 0
                local_found_ips = []

    if local_processed or local_found or local_not_found or local_timeout_errors or local_other_errors:
        apply_scan_deltas(
            processed=local_processed,
            found=local_found,
            not_found=local_not_found,
            timeout_errors=local_timeout_errors,
            other_errors=local_other_errors,
            found_ips=local_found_ips,
        )

    return 1


def handle_stop_signal(signum, frame) -> None:
    del signum, frame
    if stop_event.is_set():
        return

    stop_event.set()
    renderer.log("[!] Stop requested. Finishing in-flight requests...")


def print_banner() -> None:
    logical_cores = psutil.cpu_count(logical=True) or 0
    physical_cores = psutil.cpu_count(logical=False) or 0
    memory_gb = psutil.virtual_memory().total / (1024 ** 3)

    renderer.log("")
    renderer.log("=" * 72)
    renderer.log(" Terminal IP Scanner")
    renderer.log("=" * 72)
    renderer.log(f"[*] System: {logical_cores} logical cores | {physical_cores} physical cores | {memory_gb:.1f}GB RAM")
    renderer.log(f"[*] Mode: terminal only | no UI | no port")
    renderer.log(f"[*] Target workers: {DEFAULT_WORKERS:,}")
    renderer.log(f"[*] Request timeout: {REQUEST_TIMEOUT:.1f}s")
    renderer.log(f"[*] Retryable non-timeout retries: {RETRYABLE_RETRIES}")
    renderer.log(f"[*] HTTP engine: {'curl_cffi' if CURL_CFFI_AVAILABLE else 'requests'}")
    if DRY_RUN:
        renderer.log("[*] Dry run mode is enabled")
    renderer.log("=" * 72)
    renderer.log("")


def print_final_summary() -> None:
    snap = snapshot_stats()
    elapsed = max(time.time() - snap.start_time, 0.001)
    rate = snap.processed / elapsed if elapsed > 0 else 0.0

    renderer.log("")
    renderer.log("=" * 72)
    renderer.log("[*] Scan finished")
    renderer.log(f"[*] Processed: {snap.processed:,}/{snap.total:,}")
    renderer.log(f"[*] Found: {snap.found:,}")
    renderer.log(f"[*] Not matched: {snap.not_found:,}")
    renderer.log(f"[*] Timeout-invalid: {snap.timeout_errors:,}")
    renderer.log(f"[*] Other errors: {snap.other_errors:,}")
    renderer.log(f"[*] Average rate: {rate:,.0f} IPs/sec")
    renderer.log(f"[*] Elapsed: {format_duration(elapsed)}")
    renderer.log("=" * 72)

    if snap.found_ips:
        renderer.log("[*] Found IPs:")
        for index, ip in enumerate(snap.found_ips, start=1):
            renderer.log(f"    {index}. {ip}")
    else:
        renderer.log("[*] No matching IPs found.")


def run_threaded_scan(ip_list: List[str]) -> None:
    requested_workers = max(DEFAULT_WORKERS, 1)
    chunk_size = max(8, min(64, len(ip_list) // max(requested_workers * 6, 1)))
    index_state = {"next_index": 0}
    index_lock = threading.Lock()
    scan_done_event.clear()
    stop_event.clear()

    with stats_lock:
        stats.total = len(ip_list)
        stats.processed = 0
        stats.found = 0
        stats.not_found = 0
        stats.timeout_errors = 0
        stats.other_errors = 0
        stats.in_flight = 0
        stats.requested_workers = requested_workers
        stats.started_workers = 0
        stats.start_time = time.time()
        stats.found_ips = []

    renderer.log(f"[*] Starting threaded scan with target {requested_workers:,} workers")
    renderer.log(f"[*] Chunk size: ~{chunk_size} IPs per worker pull")

    progress_thread = threading.Thread(target=progress_reporter, daemon=True, name="progress-reporter")
    progress_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=requested_workers) as executor:
            futures = []

            for worker_number in range(requested_workers):
                try:
                    futures.append(
                        executor.submit(threaded_worker, ip_list, index_state, index_lock, chunk_size)
                    )
                    with stats_lock:
                        stats.started_workers = len(futures)
                except (RuntimeError, MemoryError, OSError) as exc:
                    started_workers = max(1, len(futures))
                    with stats_lock:
                        stats.started_workers = started_workers
                    renderer.log(
                        f"[!] Worker startup hit a limit at {worker_number + 1:,}/{requested_workers:,}. "
                        f"Continuing with {started_workers:,} worker(s). Reason: {exc}"
                    )
                    break

            if not futures:
                with stats_lock:
                    stats.started_workers = 1
                renderer.log("[!] No worker thread could be created. Falling back to inline scan.")
                threaded_worker(ip_list, index_state, index_lock, chunk_size)
                return

            with stats_lock:
                stats.started_workers = len(futures)

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    apply_scan_deltas(other_errors=1)
                    renderer.log(f"[!] Worker future error: {exc}")
    finally:
        scan_done_event.set()
        progress_thread.join(timeout=2.0)


def main() -> int:
    print_banner()

    if not IP_JSON_FILE.exists():
        renderer.log(f"[!] Missing input file: {IP_JSON_FILE}")
        return 1

    ip_list = load_ips_from_json(IP_JSON_FILE)
    if not ip_list:
        renderer.log("[!] No valid IPs found to scan.")
        return 1

    if DRY_RUN:
        renderer.log(f"[*] Dry run complete. {len(ip_list):,} IPs are ready for scanning.")
        return 0

    run_threaded_scan(ip_list)
    print_final_summary()
    return 0


if __name__ == "__main__":
    for sig_name in ("SIGINT", "SIGTERM"):
        sig = getattr(signal, sig_name, None)
        if sig is not None:
            with suppress(Exception):
                signal.signal(sig, handle_stop_signal)

    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        handle_stop_signal(None, None)
        scan_done_event.set()
        renderer.finish()
        raise SystemExit(130)
