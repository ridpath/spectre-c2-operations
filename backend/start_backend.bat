@echo off
REM Start Spectre C2 Backend in WSL

echo ==================================================
echo   Spectre C2 Tactical Bridge
echo   Starting in WSL docker-desktop
echo ==================================================
echo.

REM Check if WSL is available
wsl --list --quiet >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: WSL is not installed
    echo Install with: wsl --install
    pause
    exit /b 1
)

REM Navigate to backend directory in WSL
set BACKEND_PATH=%~dp0
set WSL_PATH=%BACKEND_PATH:\=/%
set WSL_PATH=%WSL_PATH:C:=/mnt/c%

echo Starting backend in WSL...
echo.

REM Start backend in WSL
wsl -d docker-desktop bash -c "cd '%WSL_PATH%' && chmod +x start_backend.sh && ./start_backend.sh"

pause
