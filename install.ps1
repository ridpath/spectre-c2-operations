# Spectre C2 - Windows Installation Script
# Requires: Administrator privileges

param(
    [switch]$SkipChecks = $false
)

$ErrorActionPreference = "Stop"

function Write-Header {
    param([string]$Text)
    Write-Host "`n================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "================================================`n" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Text)
    Write-Host "[+] $Text" -ForegroundColor Green
}

function Write-Info {
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Cyan
}

function Write-Warning {
    param([string]$Text)
    Write-Host "[!] $Text" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Text)
    Write-Host "[-] $Text" -ForegroundColor Red
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-Chocolatey {
    Write-Info "Checking for Chocolatey package manager..."
    
    if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Info "Installing Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        Write-Success "Chocolatey installed"
    } else {
        Write-Success "Chocolatey already installed"
    }
}

function Install-SystemDependencies {
    Write-Info "Installing system dependencies..."
    
    $packages = @(
        'nodejs',
        'python',
        'postgresql',
        'git',
        'nmap',
        'wireshark'
    )
    
    foreach ($package in $packages) {
        Write-Info "Installing $package..."
        choco install $package -y --force
    }
    
    Write-Success "System dependencies installed"
}

function Install-WSL {
    Write-Info "Checking Windows Subsystem for Linux..."
    
    $wslStatus = wsl --status 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Info "Installing WSL 2..."
        wsl --install -d Ubuntu
        Write-Warning "WSL installed - system restart may be required"
    } else {
        Write-Success "WSL already installed"
    }
    
    if (Test-Path "\\wsl.localhost\Ubuntu") {
        Write-Info "Installing Linux tools in WSL..."
        wsl sudo apt-get update
        wsl sudo apt-get install -y rtl-sdr hackrf gr-satellites gqrx-sdr direwolf multimon-ng gnuradio uhd-host soapysdr-tools
        Write-Success "Linux SDR tools installed in WSL"
    }
}

function Setup-Database {
    Write-Info "Setting up PostgreSQL database..."
    
    $pgService = Get-Service -Name postgresql* -ErrorAction SilentlyContinue
    if ($pgService) {
        Start-Service $pgService.Name
        
        $env:PGPASSWORD = "postgres"
        & "C:\Program Files\PostgreSQL\*\bin\psql.exe" -U postgres -c "CREATE DATABASE spectre_c2;" 2>$null
        & "C:\Program Files\PostgreSQL\*\bin\psql.exe" -U postgres -c "CREATE USER spectre WITH PASSWORD 'spectre_secure_pass';" 2>$null
        & "C:\Program Files\PostgreSQL\*\bin\psql.exe" -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE spectre_c2 TO spectre;" 2>$null
        
        Write-Success "Database configured"
    } else {
        Write-Warning "PostgreSQL service not found - using SQLite fallback"
    }
}

function Install-PythonDependencies {
    Write-Info "Installing Python dependencies..."
    
    Push-Location backend
    
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    python -m pip install --upgrade pip
    pip install -r requirements.txt
    deactivate
    
    Pop-Location
    
    Write-Success "Python dependencies installed"
}

function Install-NodeDependencies {
    Write-Info "Installing Node.js dependencies..."
    
    npm install
    
    Write-Success "Node.js dependencies installed"
}

function Create-EnvironmentFile {
    Write-Info "Creating environment configuration..."
    
    if (!(Test-Path "backend\.env")) {
        $jwtSecret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 64 | ForEach-Object {[char]$_})
        
        $envContent = @"
DATABASE_URL=postgresql://spectre:spectre_secure_pass@localhost:5432/spectre_c2
JWT_SECRET_KEY=$jwtSecret
ENABLE_SDR_HARDWARE=true
ENABLE_GNU_RADIO=true
ENABLE_HAMLIB=true
SPACETRACK_USERNAME=
SPACETRACK_PASSWORD=
FILE_STORAGE_PATH=./storage
"@
        
        Set-Content -Path "backend\.env" -Value $envContent
        Write-Success "Environment file created"
    } else {
        Write-Warning "Environment file already exists"
    }
}

function Initialize-Database {
    Write-Info "Initializing database..."
    
    Push-Location backend
    
    .\venv\Scripts\Activate.ps1
    python init_db.py
    deactivate
    
    Pop-Location
    
    Write-Success "Database initialized"
}

function Create-LauncherScripts {
    Write-Info "Creating launcher scripts..."
    
    $startScript = @'
@echo off
echo ================================================
echo   SPECTRE C2 PLATFORM
echo ================================================
echo.

echo [+] Starting Backend...
start "Spectre Backend" cmd /k "cd backend && venv\Scripts\activate && python backend.py"

timeout /t 3 /nobreak > nul

echo [+] Starting Frontend...
start "Spectre Frontend" cmd /k "npm run dev"

echo.
echo ================================================
echo   SERVICES STARTED
echo ================================================
echo   Frontend: http://localhost:3001
echo   Backend: http://localhost:8000
echo   API Docs: http://localhost:8000/docs
echo.
echo   Default Credentials:
echo     Username: admin
echo     Password: admin123
echo.
echo   Close windows to stop services
echo ================================================
echo.

pause
'@
    
    Set-Content -Path "start.bat" -Value $startScript
    
    Write-Success "Launcher scripts created"
}

function Main {
    Write-Header "SPECTRE C2 - Windows Installation"
    Write-Host "Platform: Windows (with WSL support)`n"
    
    if (!(Test-Administrator)) {
        Write-Error "This script requires Administrator privileges"
        Write-Host "Right-click PowerShell and select 'Run as Administrator'" -ForegroundColor Yellow
        exit 1
    }
    
    Install-Chocolatey
    Install-SystemDependencies
    Install-WSL
    Setup-Database
    Create-EnvironmentFile
    Install-PythonDependencies
    Install-NodeDependencies
    Initialize-Database
    Create-LauncherScripts
    
    Write-Header "INSTALLATION COMPLETE"
    
    Write-Host "`nTo start Spectre C2:" -ForegroundColor Cyan
    Write-Host "  .\start.bat`n" -ForegroundColor Yellow
    
    Write-Host "To start manually:" -ForegroundColor Cyan
    Write-Host "  Backend:  cd backend && .\venv\Scripts\Activate.ps1 && python backend.py" -ForegroundColor Yellow
    Write-Host "  Frontend: npm run dev`n" -ForegroundColor Yellow
    
    Write-Warning "If WSL was just installed, you may need to restart your computer"
}

Main
