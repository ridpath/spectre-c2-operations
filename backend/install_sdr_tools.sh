#!/bin/bash
# SDR Tools Installation Script for WSL/Linux
# Installs all required satellite pentesting tools

set -e

echo "=================================================="
echo "  Spectre C2 - SDR Tools Installation"
echo "=================================================="
echo ""

# Update package lists
echo "[1/8] Updating package lists..."
sudo apt update

# Install RTL-SDR tools
echo "[2/8] Installing RTL-SDR..."
sudo apt install -y rtl-sdr librtlsdr-dev

# Install HackRF tools
echo "[3/8] Installing HackRF..."
sudo apt install -y hackrf libhackrf-dev

# Install GNU Radio
echo "[4/8] Installing GNU Radio..."
sudo apt install -y gnuradio

# Install gr-satellites
echo "[5/8] Installing gr-satellites..."
sudo apt install -y python3-pip
pip3 install gr-satellites

# Install Direwolf (AX.25 decoder)
echo "[6/8] Installing Direwolf..."
sudo apt install -y direwolf

# Install UHD (USRP support)
echo "[7/8] Installing UHD..."
sudo apt install -y uhd-host libuhd-dev

# Install SoapySDR
echo "[8/8] Installing SoapySDR..."
sudo apt install -y soapysdr-tools soapysdr-module-all

echo ""
echo "=================================================="
echo "  Installation Complete!"
echo "=================================================="
echo ""
echo "Installed tools:"
echo "  - rtl_sdr, rtl_power (RTL-SDR)"
echo "  - hackrf_transfer, hackrf_sweep (HackRF)"
echo "  - gnuradio-companion, grcc (GNU Radio)"
echo "  - gr-satellites (Satellite decoder)"
echo "  - direwolf (AX.25 packet decoder)"
echo "  - uhd_fft, uhd_usrp_probe (USRP)"
echo "  - SoapySDRServer (Network SDR)"
echo ""
echo "Testing RTL-SDR detection:"
rtl_test -t || echo "No RTL-SDR device detected (this is normal if no hardware)"
echo ""
echo "Testing HackRF detection:"
hackrf_info || echo "No HackRF device detected (this is normal if no hardware)"
echo ""
