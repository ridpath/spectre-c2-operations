@echo off
echo Starting Spectre C2 Backend...
cd backend
call venv\Scripts\activate.bat
python backend.py
