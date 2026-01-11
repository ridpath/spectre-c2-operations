# Metasploit/msfvenom Installation Guide

**Current Status**: ❌ Not installed  
**Impact**: System uses mock payload generation (fully functional)  
**Priority**: Optional - Real msfvenom enables actual Metasploit payloads  
**Setup Time**: 15-30 minutes

---

## Current Behavior

Without msfvenom installed:
- ✅ **PayloadFactory works** - Uses mock payload generation
- ✅ **All templates available** - 5 payload templates functional
- ✅ **Backend operational** - No errors or failures
- ⚠️ **Payloads are simulated** - Not actual Metasploit payloads

With msfvenom installed:
- ✅ **Real Metasploit payloads** - Actual msfvenom-generated code
- ✅ **All encoders available** - x64/xor_dynamic, x64/zutto_dekiru, etc.
- ✅ **Production-ready payloads** - Can be used in real engagements

---

## Installation Options

### Option 1: Native Windows Installation (Recommended)

**Metasploit Framework for Windows**

1. **Download Metasploit Installer**:
   - Visit: https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
   - Download: `metasploitframework-latest.msi` (Windows Installer)
   - Size: ~200MB

2. **Run Installer**:
   ```powershell
   # Install to default location
   # Default: C:\metasploit-framework\bin\
   ```

3. **Verify Installation**:
   ```powershell
   # Check if msfvenom is in PATH
   where msfvenom
   
   # Or run directly
   C:\metasploit-framework\bin\msfvenom.bat --version
   ```

4. **Update Backend Configuration** (if needed):
   - Backend automatically searches common paths
   - Paths checked:
     - `C:\metasploit\bin\msfvenom.bat`
     - `C:\Program Files\Metasploit\bin\msfvenom.bat`
     - `C:\metasploit-framework\bin\msfvenom.bat`
   - No configuration needed if installed to default location

---

### Option 2: WSL (Windows Subsystem for Linux)

**Install Metasploit in WSL Ubuntu**

1. **Enable WSL** (if not already enabled):
   ```powershell
   # Run as Administrator
   wsl --install
   wsl --set-default-version 2
   ```

2. **Install Ubuntu**:
   ```powershell
   wsl --install -d Ubuntu
   ```

3. **Install Metasploit in WSL**:
   ```bash
   # Update package list
   sudo apt update

   # Install dependencies
   sudo apt install -y curl gpg

   # Add Metasploit repository
   curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
   chmod +x msfinstall
   sudo ./msfinstall

   # Verify installation
   msfvenom --version
   ```

4. **Configure Backend for WSL**:
   - Edit `backend/payload_factory.py` line 18-36
   - Add WSL path to common_paths:
   ```python
   common_paths = [
       r"C:\metasploit\bin\msfvenom.bat",
       r"C:\Program Files\Metasploit\bin\msfvenom.bat",
       "/usr/bin/msfvenom",  # WSL path
       "/opt/metasploit/msfvenom"
   ]
   ```

   - Or create wrapper script:
   ```powershell
   # Create C:\tools\msfvenom.bat
   @echo off
   wsl msfvenom %*
   ```

---

### Option 3: Kali Linux VM/Docker

**Run Metasploit in container or VM**

1. **Using Docker**:
   ```powershell
   # Pull Metasploit image
   docker pull metasploitframework/metasploit-framework

   # Run container
   docker run --rm -it metasploitframework/metasploit-framework msfvenom --version
   ```

2. **Using Kali VM**:
   - Download Kali Linux VM from: https://www.kali.org/get-kali/
   - Metasploit pre-installed
   - Access via SSH or network share

---

## Testing Installation

### Test 1: Check Version
```bash
msfvenom --version
```

Expected output:
```
metasploit v6.x.x-dev
```

### Test 2: List Payloads
```bash
msfvenom --list payloads | grep windows/x64
```

Expected: List of Windows x64 payloads

### Test 3: Generate Test Payload
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f exe -o test_payload.exe
```

Expected: Creates `test_payload.exe` file

### Test 4: Backend Integration Test
```bash
cd backend
python test_payload.py
```

Expected output with real msfvenom:
```
✅ PASSED: Template listing (5 templates, 9 formats)
✅ PASSED: Payload generation (Real msfvenom: 7168 bytes)  # Not mock!
✅ PASSED: Dropper generation (with evasion features)
```

---

## Troubleshooting

### Issue: "msfvenom not found"

**Solution**:
```powershell
# Add to PATH manually
$env:PATH += ";C:\metasploit-framework\bin"

# Or permanently:
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\metasploit-framework\bin", "User")
```

### Issue: "Permission denied" (WSL)

**Solution**:
```bash
sudo chmod +x /usr/bin/msfvenom
```

### Issue: Backend still using mock

**Check**:
1. Restart backend server after installing msfvenom
2. Check logs: `[PayloadFactory] Using mock payload generation`
3. Verify paths in `backend/payload_factory.py` line 18-36

**Fix**:
```bash
# Test if backend can find msfvenom
cd backend
python -c "from payload_factory import PayloadFactory; pf = PayloadFactory(); print(pf.msfvenom_path)"
```

Should output path if found, `None` if not found.

---

## Security Considerations

⚠️ **Important**: Metasploit payloads are detected by antivirus software

1. **Antivirus Exclusions**:
   - Add exclusion for: `C:\metasploit-framework\`
   - Add exclusion for payload output directories
   - Windows Defender may quarantine payloads

2. **Windows Defender**:
   ```powershell
   # Run as Administrator
   Add-MpPreference -ExclusionPath "C:\metasploit-framework"
   Add-MpPreference -ExclusionPath "C:\Users\<username>\payloads"
   ```

3. **Legal Notice**:
   - ⚠️ Only use on systems you own or have authorization to test
   - Unauthorized use is illegal
   - This tool is for authorized penetration testing only

---

## Performance Notes

### Mock Payload Generation (Current)
- ⚡ **Fast**: <100ms per payload
- 📦 **Small**: ~500 bytes
- ✅ **No dependencies**: Works out of the box
- ❌ **Not real**: Simulated payloads only

### Real msfvenom
- 🕐 **Slower**: 1-5 seconds per payload
- 📦 **Larger**: 7-50KB depending on template
- ⚙️ **Requires installation**: msfvenom + Ruby dependencies
- ✅ **Production-ready**: Real Metasploit payloads

---

## Backend Code Reference

The backend automatically detects msfvenom at these locations:

**File**: `backend/payload_factory.py`
**Lines**: 16-36

```python
def _find_msfvenom(self) -> Optional[str]:
    """Try to find msfvenom in common locations"""
    common_paths = [
        r"C:\metasploit\bin\msfvenom.bat",
        r"C:\Program Files\Metasploit\bin\msfvenom.bat",
        "/usr/bin/msfvenom",
        "/opt/metasploit/msfvenom"
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    # Try 'where' command on Windows
    try:
        result = subprocess.run(['where', 'msfvenom'], 
                                capture_output=True, 
                                text=True, 
                                timeout=5)
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except:
        pass
    
    return None
```

---

## Recommendation

**For Development/Testing**: 
- ✅ Current mock payloads are sufficient
- No installation needed

**For Production/Real Engagements**:
- ⚠️ Install native Windows Metasploit (Option 1)
- Provides real, operational payloads
- Best compatibility with Windows

**For Automation/CI/CD**:
- 🐳 Use Docker container (Option 3)
- Isolated environment
- Reproducible builds

---

## Next Steps After Installation

1. **Restart Backend**: `python backend/backend.py`
2. **Check Logs**: Look for `[PayloadFactory] msfvenom found at: ...`
3. **Test Generation**: Use PayloadFactory UI to generate payload
4. **Verify Output**: Check payload size (should be >5KB for real payloads)
5. **Run Tests**: `python backend/test_payload.py`

---

**Status**: Documentation complete ✅  
**System**: Fully operational with or without msfvenom  
**Choice**: User can decide based on use case
