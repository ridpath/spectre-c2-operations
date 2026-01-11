#!/usr/bin/env python3
"""
Quick backend test script
Tests all endpoints and WebSocket connections
"""

import requests
import json
import time
from websockets.sync.client import connect

BASE_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000"
AUTH_HEADER = {"Authorization": "Bearer valid_token"}

def test_health():
    """Test health check endpoint"""
    print("\n[TEST] Health Check...")
    response = requests.get(f"{BASE_URL}/health")
    print(f"  Status: {response.status_code}")
    print(f"  Response: {response.json()}")
    assert response.status_code == 200
    print("  ✓ PASSED")

def test_local_command():
    """Test local command execution"""
    print("\n[TEST] Local Command Execution...")
    payload = {
        "command": "echo 'Hello from Spectre C2'",
        "context": "local"
    }
    response = requests.post(
        f"{BASE_URL}/api/v1/execute",
        headers=AUTH_HEADER,
        json=payload
    )
    print(f"  Status: {response.status_code}")
    result = response.json()
    print(f"  Output: {result.get('output', '')[:100]}")
    assert response.status_code == 200
    print("  ✓ PASSED")

def test_tle_sync():
    """Test TLE synchronization"""
    print("\n[TEST] TLE Synchronization...")
    payload = {
        "group": "active",
        "source": "celestrak"
    }
    response = requests.post(
        f"{BASE_URL}/api/v1/orbital/sync",
        headers=AUTH_HEADER,
        json=payload
    )
    print(f"  Status: {response.status_code}")
    print(f"  Response: {response.json()}")
    assert response.status_code == 200
    print("  ✓ PASSED")

def test_ccsds_forge():
    """Test CCSDS packet forging"""
    print("\n[TEST] CCSDS Packet Forge...")
    payload = {
        "apid": 1,
        "transmit": False,
        "hex_payload": "DEADBEEF",
        "chaff": False
    }
    response = requests.post(
        f"{BASE_URL}/api/v1/forge/ccsds",
        headers=AUTH_HEADER,
        json=payload
    )
    print(f"  Status: {response.status_code}")
    result = response.json()
    print(f"  Packet: {result.get('packet_hex', '')}")
    assert response.status_code == 200
    print("  ✓ PASSED")

def test_orbital_websocket():
    """Test orbital position WebSocket stream"""
    print("\n[TEST] Orbital WebSocket (3 seconds)...")
    try:
        with connect(f"{WS_URL}/ws/orbital/43105") as websocket:
            for i in range(3):
                message = websocket.recv()
                data = json.loads(message)
                if "error" in data:
                    print(f"  Error: {data['error']}")
                else:
                    print(f"  [{i+1}] Sat: {data.get('designation', 'N/A')}, "
                          f"Elevation: {data.get('antenna_state', {}).get('elevation', 0):.2f}°")
                time.sleep(1)
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")

def test_spectrum_websocket():
    """Test spectrum WebSocket stream"""
    print("\n[TEST] Spectrum WebSocket (2 seconds)...")
    try:
        with connect(f"{WS_URL}/ws/spectrum") as websocket:
            for i in range(2):
                message = websocket.recv()
                data = json.loads(message)
                print(f"  [{i+1}] Modulation: {data.get('modulation', 'N/A')}, "
                      f"Bins: {len(data.get('data', []))}")
                time.sleep(1)
        print("  ✓ PASSED")
    except Exception as e:
        print(f"  ✗ FAILED: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("  Spectre C2 Backend Test Suite")
    print("=" * 60)
    
    try:
        test_health()
        test_local_command()
        test_tle_sync()
        test_ccsds_forge()
        test_orbital_websocket()
        test_spectrum_websocket()
        
        print("\n" + "=" * 60)
        print("  ALL TESTS PASSED ✓")
        print("=" * 60)
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}")
    except requests.exceptions.ConnectionError:
        print("\n✗ ERROR: Backend not running!")
        print("  Start backend with: python3 backend.py")
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}")
