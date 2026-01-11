#!/bin/bash

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  SPECTRE C2 - Automated Installation${NC}"
echo -e "${CYAN}  Platform: Linux (Kali/ParrotOS/Ubuntu)${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        echo -e "${GREEN}[+]${NC} Detected OS: $OS $VER"
    else
        echo -e "${RED}[-]${NC} Cannot detect OS"
        exit 1
    fi
}

check_root() {
    if [ "$EUID" -eq 0 ]; then
        echo -e "${YELLOW}[!]${NC} Running as root - some operations will be performed as root"
        IS_ROOT=true
    else
        echo -e "${GREEN}[+]${NC} Running as normal user"
        IS_ROOT=false
    fi
}

install_system_deps() {
    echo ""
    echo -e "${CYAN}[*]${NC} Installing system dependencies..."
    
    if command -v apt-get &> /dev/null; then
        if [ "$IS_ROOT" = true ]; then
            apt-get update
            apt-get install -y \
                python3 python3-pip python3-venv \
                nodejs npm \
                postgresql postgresql-contrib \
                git curl wget \
                rtl-sdr hackrf gqrx-sdr \
                gr-satellites direwolf multimon-ng \
                gnuradio uhd-host soapysdr-tools \
                nmap masscan nikto sqlmap \
                metasploit-framework \
                netcat-openbsd socat \
                jq
        else
            echo -e "${YELLOW}[!]${NC} Not root - attempting sudo..."
            sudo apt-get update
            sudo apt-get install -y \
                python3 python3-pip python3-venv \
                nodejs npm \
                postgresql postgresql-contrib \
                git curl wget \
                rtl-sdr hackrf gqrx-sdr \
                gr-satellites direwolf multimon-ng \
                gnuradio uhd-host soapysdr-tools \
                nmap masscan nikto sqlmap \
                metasploit-framework \
                netcat-openbsd socat \
                jq
        fi
    else
        echo -e "${RED}[-]${NC} apt-get not found. Unsupported package manager."
        exit 1
    fi
    
    echo -e "${GREEN}[+]${NC} System dependencies installed"
}

setup_database() {
    echo ""
    echo -e "${CYAN}[*]${NC} Setting up PostgreSQL database..."
    
    if [ "$IS_ROOT" = true ]; then
        sudo -u postgres psql -c "CREATE DATABASE spectre_c2;" 2>/dev/null || true
        sudo -u postgres psql -c "CREATE USER spectre WITH PASSWORD 'spectre_secure_pass';" 2>/dev/null || true
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE spectre_c2 TO spectre;" 2>/dev/null || true
    else
        sudo -u postgres psql -c "CREATE DATABASE spectre_c2;" 2>/dev/null || true
        sudo -u postgres psql -c "CREATE USER spectre WITH PASSWORD 'spectre_secure_pass';" 2>/dev/null || true
        sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE spectre_c2 TO spectre;" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+]${NC} Database created"
}

install_python_deps() {
    echo ""
    echo -e "${CYAN}[*]${NC} Installing Python dependencies..."
    
    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
    deactivate
    cd ..
    
    echo -e "${GREEN}[+]${NC} Python dependencies installed"
}

install_node_deps() {
    echo ""
    echo -e "${CYAN}[*]${NC} Installing Node.js dependencies..."
    
    npm install
    
    echo -e "${GREEN}[+]${NC} Node.js dependencies installed"
}

create_env_file() {
    echo ""
    echo -e "${CYAN}[*]${NC} Creating environment configuration..."
    
    if [ ! -f backend/.env ]; then
        cat > backend/.env << EOF
DATABASE_URL=postgresql://spectre:spectre_secure_pass@localhost:5432/spectre_c2
JWT_SECRET_KEY=$(openssl rand -hex 32)
ENABLE_SDR_HARDWARE=true
ENABLE_GNU_RADIO=true
ENABLE_HAMLIB=true
SPACETRACK_USERNAME=
SPACETRACK_PASSWORD=
FILE_STORAGE_PATH=./storage
EOF
        echo -e "${GREEN}[+]${NC} Environment file created at backend/.env"
    else
        echo -e "${YELLOW}[!]${NC} Environment file already exists"
    fi
}

init_database() {
    echo ""
    echo -e "${CYAN}[*]${NC} Initializing database..."
    
    cd backend
    source venv/bin/activate
    python init_db.py
    deactivate
    cd ..
    
    echo -e "${GREEN}[+]${NC} Database initialized"
}

create_launcher_scripts() {
    echo ""
    echo -e "${CYAN}[*]${NC} Creating launcher scripts..."
    
    cat > start.sh << 'EOF'
#!/bin/bash

echo "Starting Spectre C2 Platform..."
echo ""

echo "[+] Starting Backend..."
cd backend
source venv/bin/activate
python backend.py &
BACKEND_PID=$!
deactivate
cd ..

sleep 3

echo "[+] Starting Frontend..."
npm run dev &
FRONTEND_PID=$!

echo ""
echo "================================================================"
echo "  SPECTRE C2 PLATFORM RUNNING"
echo "================================================================"
echo "  Frontend: http://localhost:3001"
echo "  Backend API: http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "  Default Credentials:"
echo "    Username: admin"
echo "    Password: admin123"
echo ""
echo "  Press CTRL+C to stop all services"
echo "================================================================"
echo ""

trap "echo 'Stopping services...'; kill $BACKEND_PID $FRONTEND_PID; exit" SIGINT SIGTERM

wait
EOF
    chmod +x start.sh
    
    echo -e "${GREEN}[+]${NC} Launcher scripts created"
}

configure_sdr_permissions() {
    echo ""
    echo -e "${CYAN}[*]${NC} Configuring SDR device permissions..."
    
    if [ "$IS_ROOT" = true ]; then
        usermod -a -G plugdev $SUDO_USER 2>/dev/null || true
    else
        sudo usermod -a -G plugdev $USER 2>/dev/null || true
    fi
    
    cat > /tmp/rtl-sdr.rules << 'EOF'
SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="2838", MODE="0666"
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="604b", MODE="0666"
SUBSYSTEM=="usb", ATTRS{idVendor}=="1d50", ATTRS{idProduct}=="6089", MODE="0666"
EOF
    
    if [ "$IS_ROOT" = true ]; then
        mv /tmp/rtl-sdr.rules /etc/udev/rules.d/20-rtlsdr.rules
        udevadm control --reload-rules
        udevadm trigger
    else
        sudo mv /tmp/rtl-sdr.rules /etc/udev/rules.d/20-rtlsdr.rules
        sudo udevadm control --reload-rules
        sudo udevadm trigger
    fi
    
    echo -e "${GREEN}[+]${NC} SDR permissions configured"
}

main() {
    detect_os
    check_root
    install_system_deps
    setup_database
    create_env_file
    install_python_deps
    install_node_deps
    init_database
    create_launcher_scripts
    configure_sdr_permissions
    
    echo ""
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}  INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo ""
    echo -e "${CYAN}To start Spectre C2:${NC}"
    echo -e "  ${YELLOW}./start.sh${NC}"
    echo ""
    echo -e "${CYAN}To start manually:${NC}"
    echo -e "  Backend:  ${YELLOW}cd backend && source venv/bin/activate && python backend.py${NC}"
    echo -e "  Frontend: ${YELLOW}npm run dev${NC}"
    echo ""
    echo -e "${YELLOW}[!]${NC} You may need to log out and back in for group permissions to take effect"
    echo ""
}

main
