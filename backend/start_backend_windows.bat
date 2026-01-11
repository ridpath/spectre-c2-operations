@echo off
REM Start Spectre C2 Backend on Windows (native Python)

echo ==================================================
echo   Spectre C2 Tactical Bridge
echo   FastAPI Backend Server (Windows Native)
echo ==================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed
    echo Install from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Navigate to backend directory
cd /d "%~dp0"

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating Python virtual environment...
    python -m venv venv
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install/upgrade requirements
echo Installing Python dependencies...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

echo.
echo Starting backend server on http://localhost:8000
echo Press Ctrl+C to stop
echo.

REM Start server
python backend.py

pause
