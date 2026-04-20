# 🚀 IP Scanner Pro - Setup Guide

## Quick Start

### Step 1: Install Dependencies

Open **Command Prompt** or **PowerShell** in this directory and run:

```bash
# Install all required packages
pip install -r requirements_simple.txt
```

Or install individually:
```bash
pip install fastapi uvicorn requests psutil python-multipart
```

### Step 2: Run the Scanner

```bash
python scanner_simple.py
```

### Step 3: Open Web UI

Navigate to: **http://localhost:8080**

---

## File Overview

| File | Description |
|------|-------------|
| `scanner.py` | Full version with curl_cffi (Chrome impersonation) |
| `scanner_simple.py` | Standard requests version (easier setup) |
| `ip.json` | Your IP list (CIDR prefixes supported) |
| `found/` | Directory where matching IPs are saved |
| `run.bat` | Windows launcher script |

---

## System Requirements

| Spec | Minimum | Recommended |
|------|---------|-------------|
| CPU | 4 cores | 16 cores |
| RAM | 4 GB | 32 GB |
| Python | 3.8 | 3.11+ |
| Network | 10 Mbps | 100 Mbps+ |

---

## Performance Tuning

### For 16 Cores / 32GB RAM (Target: 2.7M IPs in 40 min)

The scanner auto-detects your system and uses:
- **Workers**: ~4000
- **Threads**: ~10000
- **Target Rate**: ~1125 IPs/second

### To achieve maximum speed:

1. **Close other applications** - Free up CPU/RAM
2. **Use wired ethernet** - More stable than WiFi
3. **Disable antivirus** temporarily (can slow I/O)
4. **Run as Administrator** (Windows) - Higher priority

---

## How It Works

1. **Loads IP JSON** - Reads CIDR prefixes and expands to individual IPs
2. **Creates Batches** - Splits IPs into small batches for workers
3. **Spawns Workers** - ThreadPoolExecutor with thousands of workers
4. **Scans Each IP** - Sends GET request, checks for target error
5. **Saves Matches** - Writes to `found/` directory + broadcasts to UI

---

## Understanding the JSON Format

Your `ip.json` has AWS-style prefixes:

```json
{
  "prefixes": [
    {"ip_prefix": "52.94.76.0/22", "region": "ap-south-1"},
    {"ip_prefix": "15.220.216.0/22", "region": "ap-south-1"}
  ]
}
```

Each `/22` CIDR = 1022 IPs. Current count: ~284 prefixes = ~889,813 IPs.

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'xxx'"
```bash
pip install -r requirements_simple.txt
```

### Scanner is slow
- Check CPU usage in the UI
- If CPU < 50%, increase workers in code (line ~150)
- If CPU > 90%, decrease workers
- Check network bandwidth

### "Too many open files" error (Linux/Mac)
```bash
ulimit -n 65535
```

### Windows: Connection errors
- Disable Windows Defender Real-time protection temporarily
- Or add Python to exclusions

### Out of memory
- Reduce batch size in `scan_manager()` function
- Close other applications

---

## Command Line Usage

If you want to run without the web UI, modify the code to add a CLI mode, or use:

```python
# In Python console
from scanner_simple import load_ips_from_json, scan_manager
from pathlib import Path

ips = load_ips_from_json(Path("ip.json"))
scan_manager(ips)  # This starts the scan
```

---

## Target Error

The scanner looks for this exact text in responses:

```
Internal server error: Request method 'GET' is not supported
```

If found, the IP is saved to `found/` directory.

---

## File Output Format

Each found IP gets a file: `found/<ip>.txt`

Example: `found/192_168_1_1.txt`

```
IP: 192.168.1.1
Timestamp: 2026-04-08T00:30:00
Status Code: 405

==================================================
Response:
Internal server error: Request method 'GET' is not supported
```

---

## WebSocket API

Connect to `ws://localhost:8080/ws`

### Commands:

**Start Scan:**
```json
{"action": "start"}
```

**Stop Scan:**
```json
{"action": "stop"}
```

**Get Stats:**
```json
{"action": "get_stats"}
```

**Get Found IPs:**
```json
{"action": "get_found"}
```

---

## Tips for Maximum Performance

1. **Run on Linux** if possible - better thread scheduling
2. **Use SSD** for `found/` directory - faster I/O
3. **Increase file descriptor limits**
4. **Disable all logging** (modify code if needed)
5. **Use dedicated network interface**

---

## Safety Notes

⚠️ **This tool makes thousands of concurrent HTTPS requests**

- Only scan IPs you have permission to scan
- May trigger rate limits or firewall blocks
- Use responsibly
