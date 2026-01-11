# Spectre C2 Tactical Bridge - Backend

FastAPI backend providing WinRM execution, satellite orbital mechanics, and SDR tool integration.

## Features

### Implemented Endpoints

#### Command Execution
- **POST** `/api/v1/execute` - Execute WinRM or local shell commands
- Supports NTLM, Kerberos, CredSSP authentication
- Timeout protection (30s default)
- Full stdout/stderr capture

#### Satellite Orbital Mechanics
- **WebSocket** `/ws/orbital/{norad_id}` - Real-time satellite position streaming
- **POST** `/api/v1/orbital/sync` - Sync TLE data from Celestrak
- Uses Skyfield + SGP4 for accurate orbital calculations
- Calculates azimuth, elevation, range, doppler shift

#### SDR Integration
- **POST** `/api/v1/iq/dump` - Capture IQ samples via rtl_sdr
- **POST** `/api/v1/forge/ccsds` - Forge CCSDS space packets
- **WebSocket** `/ws/spectrum` - Real-time spectrum data stream

#### Health Check
- **GET** `/health` - Server status and uptime

## Installation

### Windows (WSL2)

#### Option 1: Quick Start (Batch File)
```cmd
cd backend
start_backend.bat
```

#### Option 2: Manual WSL Setup
```bash
# In WSL terminal
cd /mnt/c/Users/rootless/.zenflow/worktrees/spectre-ba40/backend

# Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start server
python3 backend.py
```

### Linux/macOS
```bash
cd backend
chmod +x start_backend.sh
./start_backend.sh
```

## SDR Tools Installation

Install all satellite pentesting tools:

```bash
# In WSL/Linux
cd backend
chmod +x install_sdr_tools.sh
sudo ./install_sdr_tools.sh
```

**Installed tools:**
- RTL-SDR: `rtl_sdr`, `rtl_power`, `rtl_test`
- HackRF: `hackrf_transfer`, `hackrf_sweep`, `hackrf_info`
- GNU Radio: `gnuradio-companion`, `grcc`
- gr-satellites: Satellite telemetry decoder
- Direwolf: AX.25 packet decoder
- UHD: USRP tools (`uhd_fft`, `uhd_usrp_probe`)
- SoapySDR: Network SDR server

## Configuration

### Environment Variables (Optional)

Create `.env` file:
```bash
# Authentication token (matches frontend)
AUTH_TOKEN=valid_token

# Default ground station coordinates
OBSERVER_LAT=37.7749
OBSERVER_LNG=-122.4194
OBSERVER_ALT=0
```

## API Examples

### Execute Local Command
```bash
curl -X POST http://localhost:8000/api/v1/execute \
  -H "Authorization: Bearer valid_token" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "whoami",
    "context": "local"
  }'
```

### Execute WinRM Command
```bash
curl -X POST http://localhost:8000/api/v1/execute \
  -H "Authorization: Bearer valid_token" \
  -H "Content-Type: application/json" \
  -d '{
    "command": "ipconfig",
    "context": "remote",
    "connection": {
      "host": "10.10.11.23",
      "port": 5985,
      "username": "Administrator",
      "password": "P@ssw0rd",
      "use_ssl": false,
      "auth_method": "ntlm"
    }
  }'
```

### Get Satellite Position Stream
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/orbital/43105');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Satellite position:', data.coords);
  console.log('Antenna pointing:', data.antenna_state);
};
```

### Sync TLE Data
```bash
curl -X POST http://localhost:8000/api/v1/orbital/sync \
  -H "Authorization: Bearer valid_token" \
  -H "Content-Type: application/json" \
  -d '{
    "group": "active",
    "source": "celestrak"
  }'
```

### Capture IQ Samples
```bash
curl -X POST http://localhost:8000/api/v1/iq/dump \
  -H "Authorization: Bearer valid_token" \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "satellite_pass_20260110"
  }'
```

### Forge CCSDS Packet
```bash
curl -X POST http://localhost:8000/api/v1/forge/ccsds \
  -H "Authorization: Bearer valid_token" \
  -H "Content-Type: application/json" \
  -d '{
    "apid": 1,
    "transmit": false,
    "hex_payload": "DEADBEEF",
    "chaff": false
  }'
```

## Testing

### Health Check
```bash
curl http://localhost:8000/health
# Expected: {"status":"operational","timestamp":"2026-01-10T..."}
```

### Interactive API Docs
Open in browser:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Dependencies

### Python Packages (requirements.txt)
- **fastapi**: Web framework
- **uvicorn**: ASGI server
- **pywinrm**: Windows Remote Management client
- **skyfield**: Satellite position calculations
- **sgp4**: Orbital mechanics
- **websockets**: Real-time data streaming

### System Dependencies (Linux/WSL)
- Python 3.10+
- librtlsdr (RTL-SDR drivers)
- libhackrf (HackRF drivers)
- gnuradio (SDR framework)
- direwolf (Packet decoder)

## Troubleshooting

### Backend won't start
```bash
# Check Python version (3.10+ required)
python3 --version

# Check dependencies
pip list | grep fastapi

# Check port availability
netstat -an | grep 8000
```

### WinRM connection fails
```bash
# Test from command line
python3 -c "from winrm.protocol import Protocol; print('pywinrm installed')"

# Check Windows target has WinRM enabled
# On target: winrm quickconfig
```

### SDR tools not found
```bash
# Reinstall SDR tools
sudo ./install_sdr_tools.sh

# Check RTL-SDR
which rtl_sdr

# Check USB devices
lsusb | grep -i realtek
```

### WebSocket connection fails
```bash
# Check CORS settings in backend.py
# Ensure frontend URL is in allow_origins

# Test WebSocket
wscat -c ws://localhost:8000/ws/orbital/43105
```

## Security Notes

**WARNING**: This backend is for authorized security research only.

- Default token (`valid_token`) is for development only
- Change `AUTH_TOKEN` in production
- Use SSL/TLS for WinRM connections
- Validate all transmission frequencies against FCC regulations
- Obtain written authorization before satellite operations

## Performance

- **WebSocket updates**: 1 Hz orbital position, 10 Hz spectrum data
- **TLE caching**: In-memory cache prevents redundant API calls
- **Command timeout**: 30s default (configurable)
- **Concurrent WebSockets**: Supports multiple satellite streams

## Architecture

```
Frontend (React)
    ↓ HTTP/WebSocket
Tactical Bridge (FastAPI)
    ↓
├─→ WinRM Client (pywinrm)
├─→ Orbital Mechanics (skyfield/sgp4)
├─→ SDR Tools (rtl_sdr, hackrf, etc.)
└─→ TLE Data (Celestrak API)
```

## License

Research and educational use only. See main repository for full license.
