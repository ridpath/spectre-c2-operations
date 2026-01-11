@echo off
echo ===================================================
echo SPECTRE C2 - Starting Development Servers
echo ===================================================
echo.

echo Starting backend server on http://localhost:8000...
start "Spectre Backend" cmd /k "cd backend && python -m uvicorn backend:app --reload --host 0.0.0.0 --port 8000"

echo Waiting 3 seconds for backend to start...
timeout /t 3 /nobreak >nul

echo Starting frontend server on http://localhost:3000...
start "Spectre Frontend" cmd /k "npm run dev"

echo.
echo ===================================================
echo Servers starting in separate windows...
echo ===================================================
echo.
echo Backend:  http://localhost:8000
echo Frontend: http://localhost:3000
echo API Docs: http://localhost:8000/docs
echo.
echo Login Credentials:
echo   Username: admin
echo   Password: admin123
echo.
echo ===================================================
pause
