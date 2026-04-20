# 🚀 IP Scanner Pro

High-Performance Multi-threaded IP Scanner with WebSocket UI

Optimized to target **2.7 million IPs in ~20 minutes** on a 16-core / 32GB RAM server.

## Features

- ⚡ **Aggressive Multi-threading** - Dynamically adjusts workers based on CPU cores + memory
- 🔍 **CIDR Expansion** - Automatically expands CIDR prefixes from JSON
- 🌐 **Real-time Web UI** - WebSocket-connected dashboard with live updates
- 💾 **Auto-save Results** - Found IPs saved to `found/` directory automatically
- 🖥️ **System Resource Aware** - Monitors CPU/RAM and adjusts workers dynamically
- 🔒 **Chrome Impersonation** - Uses `curl_cffi` for realistic browser requests
- ⏱️ **Timeout Handling** - Handles connection timeouts gracefully

## Installation

### Windows
```batch
# Run the setup script
run.bat
```

### Linux/macOS
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python scanner.py
```

## Usage

1. **Start the server:**
   ```bash
   python scanner.py
   ```

2. **Open Web UI:**
   Navigate to `http://localhost:8080`

3. **Start Scanning:**
   - Click "Start Scan" button
   - Monitor progress in real-time
   - Found IPs appear instantly in the UI

## Configuration

The scanner automatically optimizes based on your system:
- **Workers**: `physical_cores × 250` (adjusts based on CPU%)
- **Threads**: `workers × 3` (max 10,000)

For a 16-core / 32GB system:
- ~4000 workers
- ~10000 threads
- Target: ~2250 IPs/second for a ~20-minute run

## File Structure

```
.
├── scanner.py          # Main scanner + WebSocket server
├── requirements.txt    # Python dependencies
├── run.bat            # Windows launcher
├── ip.json            # Input IPs (CIDR prefixes supported)
└── found/             # Output directory for matching IPs
    ├── 192_168_1_1.txt
    └── ...
```

## JSON Format

### CIDR Prefixes (AWS IP ranges style)
```json
{
  "prefixes": [
    {"ip_prefix": "52.94.76.0/22", "region": "ap-south-1"},
    {"ip_prefix": "15.220.216.0/22", "region": "ap-south-1"}
  ]
}
```

### Simple IP List
```json
["192.168.1.1", "10.0.0.1", "172.16.0.1"]
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web UI |
| `WS /ws` | WebSocket for real-time updates |

### WebSocket Commands

```json
// Start scan
{"action": "start"}

// Stop scan
{"action": "stop"}

// Get current stats
{"action": "get_stats"}

// Get all found IPs
{"action": "get_found"}
```

## Performance Tips

1. **Close other applications** to free up CPU/RAM
2. **Use wired connection** for stable network
3. **Adjust timeout** in `scan_config.timeout` if needed
4. **Adjust target duration** in `scan_config.target_scan_minutes` if you want a different ETA goal
5. **Monitor system** - watch CPU/RAM in the Web UI

## Troubleshooting

### curl_cffi not available
```bash
pip install curl_cffi
```

### Too many open files (Linux)
```bash
ulimit -n 65535
```

### Slow scan speed
- Check CPU usage - may be throttling
- Check network bandwidth
- Verify `ip.json` has valid CIDRs

## Requirements

- Python 3.8+
- 4GB+ RAM (16GB+ recommended)
- Multi-core CPU recommended

## License

MIT
