#!/bin/bash
# Start Spectre C2 Backend Server

cd "$(dirname "$0")"

echo "=================================================="
echo "  Spectre C2 Tactical Bridge"
echo "  FastAPI Backend Server"
echo "=================================================="
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install/upgrade requirements
echo "Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

echo ""
echo "Starting backend server on http://localhost:8000"
echo "Press Ctrl+C to stop"
echo ""

# Start server
python3 backend.py
