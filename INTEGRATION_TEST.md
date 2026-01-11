# Backend Integration Test Guide

## Quick Start

### 1. Start Backend
```bash
cd backend
python backend.py
```

Expected output:
```
Starting Spectre C2 Operations Center v5.0.0
Database: spectre_c2.db
INFO:     Started server process
INFO:     Uvicorn running on http://0.0.0.0:8000
```

### 2. Verify Backend Health
```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "operational",
  "app": "Spectre C2 Operations Center",
  "version": "5.0.0",
  "timestamp": "2026-01-11T..."
}
```

### 3. Test Authentication
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"admin123\"}"
```

Expected: JWT access_token in response

### 4. Test Module Execution
```bash
# Get your token from step 3, then:
curl -X POST http://localhost:8000/api/v1/modules/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d "{\"command\":\"relay-init --hops LEO-GEO-LEO\"}"
```

Expected: Module execution result with success:true

### 5. Test Nmap Scan (Requires nmap installed)
```bash
curl -X POST http://localhost:8000/api/v1/vulnerabilities/scan \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d "{\"target\":\"127.0.0.1\",\"scan_type\":\"quick\",\"ports\":\"1-100\"}"
```

Expected: Scan result with hosts and findings

### 6. Test APT Chains
```bash
# List available chains
curl http://localhost:8000/api/v1/apt/chains \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Execute orbital compromise chain
curl -X POST http://localhost:8000/api/v1/apt/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE" \
  -d "{\"chain_id\":\"apt-orbital-compromise\",\"pause_on_error\":true}"
```

Expected: Chain execution with step_results array

---

## Frontend Integration Test

### 1. Start Frontend
```bash
npm run dev
```

Visit: `http://localhost:5173`

### 2. Login
- Username: `admin`
- Password: `admin123`

### 3. Test Terminal Module Execution
1. Navigate to Dashboard
2. Open Terminal (bottom section)
3. Click "Local Core" button
4. Execute command: `relay-init --hops LEO-GEO-LEO`
5. Verify output shows module execution result

### 4. Test Nmap Scanning
1. Navigate to Satellite section
2. Select any satellite
3. Click "Vulnerability" tab
4. Click "Nmap Scan" mode
5. Enter target: `127.0.0.1`
6. Click "Quick Scan"
7. Verify results appear (requires nmap installed)

### 5. Test Relay Tab
1. Navigate to Satellite section
2. Click "Relay" tab
3. See backend integration instructions
4. Use Terminal to execute relay commands

### 6. Test WebSocket Connection
1. Navigate to Satellite section
2. Select a satellite (e.g., ISS)
3. Verify orbital data updates in real-time
4. Check browser console for WebSocket messages

---

## Module Execution Examples

All these work from Terminal (Local Core) or via moduleService:

### Reconnaissance
```
enum-domain --full
scan-network --subnet 192.168.1.0/24
bloodhound --stealth
enum-processes
```

### Exploitation
```
exploit-eternalblue --target 192.168.1.10
exploit-zerologon --target DC01.HTB.LOCAL
kerberoast --auto
```

### Post-Exploitation
```
harvest-creds --lsass
lateral-wmi --target DC01
steal-token --user SYSTEM
exfil-smb --path C:\\Users --target 192.168.1.100
```

### Persistence
```
persist-schtask --trigger daily --name MicrosoftUpdate
golden-ticket --user Administrator --domain HTB.LOCAL
persist-wmi --event ProcessStart --filter notepad.exe
```

### Orbital Operations
```
scan-orbital --freq 437.5
gs-mimic --norad 43105
ccsds-inject --apid 100 --cmd SAFE_MODE
ccsds-tm-spoof --apid 200 --health NOMINAL
relay-init --hops LEO-GEO-LEO
relay-status
persist-aos --norad 25544
```

---

## APT Chain Execution Test

### Via Terminal
1. Open Terminal, switch to "Local Core"
2. Not directly available in Terminal (use browser console)

### Via Browser Console
```javascript
// Import service
const { aptService } = await import('/src/services/aptService.ts');

// List chains
const chains = await aptService.listChains();
console.log('Available chains:', chains.chains.map(c => c.id));

// Execute orbital compromise chain
const result = await aptService.executeChain({
  chain_id: 'apt-orbital-compromise',
  pause_on_error: true
});

console.log('Execution ID:', result.execution_id);
console.log('Steps completed:', result.completed_steps);
console.log('Step results:', result.step_results);
```

---

## Expected Backend Behavior

### Module Execution
- **Success**: Returns `{success: true, module: "...", output: "...", execution_id: "..."}`
- **Privilege Error**: Returns `{success: false, error_type: "privilege_error", required_privilege: "..."}`
- **Not Found**: Returns `{success: false, error_type: "module_not_found"}`

### Nmap Scanning
- **Quick Scan**: ~5-10 seconds for local targets
- **Full Scan**: Can take minutes depending on target
- **SMB Scan**: Checks ports 139/445 for EternalBlue
- **Results**: Contains `hosts`, `findings`, `total_findings`

### APT Chains
- **Step-by-step execution** with configurable delays
- **Auto-pause on error** if `pause_on_error: true`
- **Evidence creation** for successful steps
- **Audit logging** of all executions

---

## Troubleshooting

### Backend Won't Start
```bash
# Check if port 8000 is in use
netstat -ano | findstr :8000

# Kill existing process
taskkill /PID <PID> /F

# Reinstall dependencies
cd backend
pip install -r requirements.txt
```

### Module Execution Fails
- **401 Unauthorized**: Token expired or invalid, login again
- **403 Forbidden**: Insufficient role (need operator/admin)
- **Module not found**: Check module name spelling
- **Privilege error**: Module requires higher integrity level

### Nmap Scans Fail
```bash
# Verify nmap installed
nmap --version

# Check nmap path in backend/vuln_scanner.py
# Line 14: nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
```

### WebSocket Connection Fails
- Check CORS settings in backend.py
- Verify backend is running on port 8000
- Check browser console for errors
- Try refreshing page after backend restart

---

## Performance Notes

### Module Execution
- Average: 100-500ms per module
- Network modules: 1-10 seconds
- Exploit modules: 2-5 seconds

### Nmap Scans
- Quick scan (1-1000 ports): 5-30 seconds
- Full scan (-p-): 5-20 minutes
- SMB vuln scan: 10-30 seconds
- Discovery scan: 5-15 seconds

### APT Chains
- Orbital compromise: ~30 seconds (5 steps)
- Domain dominance: ~25 seconds (5 steps)
- Ransomware sim: ~30 seconds (5 steps)

---

## Security Notes

1. **Database contains admin password hash**: Change default admin123 in production
2. **JWT secret is dev key**: Update JWT_SECRET_KEY in .env for production
3. **Nmap requires elevation**: Some scans need admin/root privileges
4. **CORS is wide open**: Restrict CORS_ORIGINS in production
5. **No rate limiting on modules**: Can be abused, implement throttling

---

## Next Integration Steps

1. **Evidence Vault**: Connect to backend evidence retrieval
2. **Mission Planner**: Link to exploit_engine.py for automated execution
3. **Report Generator**: Pull data from backend for comprehensive reports
4. **File Upload**: Test IQ recording upload to backend storage
5. **User Management**: Admin panel for user creation/deletion
