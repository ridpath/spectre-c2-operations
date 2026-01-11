# Backend Integration Documentation

## Overview
All frontend components are now fully integrated with the FastAPI backend at `http://localhost:8000/api/v1`.

## Services Created

### 1. **nmapService** (`services/nmapService.ts`)
Integrates nmap-based network vulnerability scanning from the UI.

**Backend Endpoint**: `POST /api/v1/vulnerabilities/scan`

**Methods**:
- `quickScan(target, ports, missionId?)` - Fast TCP SYN scan (ports 1-1000)
- `fullScan(target, missionId?)` - Comprehensive scan with version detection
- `vulnScan(target, cve?, missionId?)` - NSE vulnerability scripts
- `smbScan(target, missionId?)` - SMB-specific exploits (EternalBlue, MS17-010)
- `rdpScan(target, missionId?)` - RDP vulnerabilities (BlueKeep)
- `serviceScan(target, service, missionId?)` - Service-specific scans
- `networkDiscovery(subnet, missionId?)` - Host discovery

**UI Integration**: VulnerabilityScanner component now has "Nmap Scan" tab

**Example**:
```typescript
import { nmapService } from '../services/nmapService';

const result = await nmapService.smbScan('192.168.1.10');
console.log(result.findings); // Array of vulnerabilities found
```

---

### 2. **moduleService** (`services/moduleService.ts`)
Executes tactical modules from module_executor.py backend.

**Backend Endpoint**: `POST /api/v1/modules/execute`

**Methods**:
- `executeModule(command, missionId?)` - Execute any tactical module
- `listModules(category?)` - List all available modules
- `isOrbitalModule(name)` - Check if module is orbital-specific
- `isReconModule(name)` - Check if module is reconnaissance
- `isExploitModule(name)` - Check if module is exploit

**Supported Modules**:
- **Recon**: enum-domain, scan-network, scan-ports, bloodhound, enum-processes
- **Exploit**: exploit-eternalblue, exploit-zerologon, exploit-printnightmare, kerberoast
- **PostEx**: harvest-creds, lateral-psexec, lateral-wmi, steal-token, exfil-smb
- **Persist**: persist-schtask, persist-registry, persist-service, golden-ticket
- **Orbital**: scan-orbital, gs-mimic, ccsds-inject, ccsds-tm-spoof, relay-init, relay-status, persist-aos

**UI Integration**: Terminal component (Local Core context)

**Example**:
```typescript
import { moduleService } from '../services/moduleService';

const result = await moduleService.executeModule('relay-init --hops LEO-GEO-LEO');
if (result.success) {
  console.log(result.output);
} else {
  console.error(result.error, result.error_type);
}
```

---

### 3. **aptService** (`services/aptService.ts`)
Executes multi-step APT (Advanced Persistent Threat) attack chains.

**Backend Endpoints**:
- `GET /api/v1/apt/chains` - List all tactical chains
- `GET /api/v1/apt/chains/{chain_id}` - Get chain details
- `POST /api/v1/apt/execute` - Execute attack chain
- `GET /api/v1/apt/history` - Get execution history

**Methods**:
- `listChains()` - Get all available APT chains
- `getChainDetails(chainId)` - Get specific chain steps
- `executeChain(request)` - Execute full attack chain
- `getExecutionHistory()` - View past executions

**Available Chains**:
- `apt-domain-dominance` - AD takeover (APT29 mimicry)
- `apt-ransomware-sim` - Ransomware deployment (BlackCat/ALPHV)
- `apt-supply-chain` - Build system infiltration (APT41)
- `apt-orbital-compromise` - Satellite ground station takeover
- `apt-edr-evasion` - EDR evasion techniques

**Example**:
```typescript
import { aptService } from '../services/aptService';

const result = await aptService.executeChain({
  chain_id: 'apt-orbital-compromise',
  variables: { 'norad': '43105' },
  pause_on_error: true,
  mission_id: 'mission-123'
});

console.log(`Completed ${result.completed_steps}/${result.total_steps} steps`);
```

---

### 4. **relayService** (`services/relayService.ts`)
Manages multi-hop orbital relay chains using backend modules.

**Backend Integration**: Uses moduleService to execute `relay-init` and `relay-status`

**Methods**:
- `initializeRelay(hopPattern, missionId?)` - Initialize relay chain
- `getRelayStatus(missionId?)` - Check relay status
- `parseMockRelayData(satellites)` - Generate relay visualization data

**UI Integration**: SatelliteOrchestrator "Relay" tab

**Example**:
```typescript
import { relayService } from '../services/relayService';

const result = await relayService.initializeRelay('LEO-GEO-LEO');
if (result.success) {
  console.log('Relay initialized:', result.output);
}

const status = await relayService.getRelayStatus();
```

---

## Terminal Integration

The Terminal component (`components/Terminal.tsx`) now automatically routes commands to backend:

1. **Local Core context** + **module command** → `moduleService.executeModule()`
2. **Remote WinRM context** → `POST /api/v1/execute` (remote execution)
3. **Fallback** → Mock simulation for testing

**Module Command Detection**: Commands starting with:
- `enum-domain`, `scan-network`, `bloodhound`, `exploit-*`, `ccsds-inject`, `relay-init`, etc.

**Usage**:
1. Switch to "Local Core" in Terminal
2. Type any module command: `relay-init --hops LEO-GEO-LEO`
3. Terminal automatically sends to backend module executor
4. Results displayed with module execution ID and timestamp

---

## Vulnerability Scanner Integration

VulnerabilityScanner now has two modes:

### **Satellite CVE Mode** (Default)
- Uses `POST /api/v1/vulnerabilities/scan` with satellite_name
- Returns satellite-specific CVEs from NVD database
- Backend: nvd_scanner.py

### **Nmap Scan Mode**
- Uses `POST /api/v1/vulnerabilities/scan` with target IP/hostname
- Executes real nmap scans via vuln_scanner.py
- Scan types: Quick, Full, SMB, RDP, Vuln Scripts
- Results show: open ports, services, versions, CVEs, NSE script output

**Usage**:
1. Click "Nmap Scan" tab in VulnerabilityScanner
2. Enter target IP (e.g., `192.168.1.10`)
3. Choose scan type (SMB Vuln recommended for Windows targets)
4. View results: hosts found, findings, severity, CVEs

---

## WebSocket Endpoints (Already Implemented)

### `/ws/orbital/{norad_id}`
Real-time satellite orbital data:
- Lat/lng coordinates
- Altitude, velocity
- Antenna azimuth/elevation
- Tracking status

### `/ws/spectrum`
Live SDR spectrum data (when SDR hardware enabled):
- FFT data
- Center frequency
- Bandwidth
- Sample rate

**Frontend Usage**: Already integrated in SatelliteOrchestrator and SpectrumStudio

---

## Authentication Flow

All services use JWT tokens from localStorage:

```typescript
function getAuthToken(): string {
  return localStorage.getItem('access_token') || '';
}
```

**Login Flow**:
1. User logs in via LoginScreen
2. `POST /api/v1/auth/login` → Returns access_token
3. Token stored in localStorage
4. All subsequent API calls include: `Authorization: Bearer {token}`

**Current Admin Credentials**:
- Username: `admin`
- Password: `admin123`

---

## Testing Backend Integration

### 1. Start Backend
```bash
cd backend
python backend.py
```

Backend runs at: `http://localhost:8000`
API docs: `http://localhost:8000/docs`

### 2. Start Frontend
```bash
npm run dev
```

Frontend runs at: `http://localhost:5173`

### 3. Test Module Execution
1. Login with admin/admin123
2. Navigate to Dashboard
3. Open Terminal
4. Switch to "Local Core"
5. Execute: `relay-init --hops LEO-GEO-LEO`
6. Check backend logs for module execution

### 4. Test Nmap Scanning
1. Navigate to Satellite section
2. Click "Vulnerability" tab
3. Switch to "Nmap Scan"
4. Enter target: `192.168.1.1` (or any internal IP)
5. Click "SMB Vuln" or "Quick Scan"
6. Wait for results (requires nmap installed on backend system)

### 5. Test APT Chain
```typescript
// In browser console:
const { aptService } = await import('./services/aptService.ts');
const chains = await aptService.listChains();
console.log(chains);

const result = await aptService.executeChain({
  chain_id: 'apt-orbital-compromise'
});
console.log(result.step_results);
```

---

## Backend Requirements

### Python Dependencies
```bash
pip install fastapi uvicorn sqlalchemy pydantic python-multipart
pip install skyfield requests numpy python-nmap
pip install bcrypt passlib python-jose
```

### System Dependencies
- **Nmap**: Required for network scanning
  - Windows: Download from https://nmap.org/download.html
  - Linux: `sudo apt install nmap`
  - Path configured in vuln_scanner.py: `C:\Program Files (x86)\Nmap\nmap.exe`

---

## Mission Integration

All services support optional `mission_id` parameter to link actions to missions:

```typescript
// Nmap scan linked to mission
await nmapService.smbScan('192.168.1.10', 'mission-uuid-123');

// Module execution linked to mission
await moduleService.executeModule('bloodhound --stealth', 'mission-uuid-123');

// APT chain linked to mission
await aptService.executeChain({
  chain_id: 'apt-domain-dominance',
  mission_id: 'mission-uuid-123'
});
```

Evidence automatically created in database for successful operations.

---

## Troubleshooting

### Module Execution Fails
- Check backend logs: `python backend.py`
- Verify authentication token in localStorage
- Ensure user role is "operator" or "admin"

### Nmap Scans Fail
- Verify nmap is installed: `nmap --version`
- Check nmap path in backend/vuln_scanner.py line 14
- Run backend with elevated privileges if needed

### WebSocket Connection Issues
- Check CORS settings in backend.py
- Verify WebSocket URL matches backend address
- Check browser console for connection errors

---

## Next Steps

1. **Add UI for APT Chain Execution**: Create AttackChainPlaybook UI integration
2. **Mission Planner Backend**: Connect mission creation to exploit_engine.py
3. **Evidence Vault Integration**: Display mission evidence from backend
4. **Nmap Progress Updates**: Add WebSocket for real-time scan progress
5. **Module Browser UI**: Visual catalog of all available modules

---

## API Endpoint Reference

| Endpoint | Method | Purpose | Service |
|----------|--------|---------|---------|
| `/api/v1/modules/execute` | POST | Execute tactical module | moduleService |
| `/api/v1/modules/list` | GET | List all modules | moduleService |
| `/api/v1/vulnerabilities/scan` | POST | Nmap/CVE scan | nmapService |
| `/api/v1/apt/chains` | GET | List APT chains | aptService |
| `/api/v1/apt/execute` | POST | Execute APT chain | aptService |
| `/api/v1/apt/history` | GET | Get execution history | aptService |
| `/ws/orbital/{norad_id}` | WS | Real-time orbital data | SatelliteOrchestrator |
| `/ws/spectrum` | WS | Live spectrum data | SpectrumStudio |

All endpoints require `Authorization: Bearer {token}` header except `/health`.
