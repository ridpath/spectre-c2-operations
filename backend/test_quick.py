#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quick backend functionality tests"""

import sys
import io
import requests
from datetime import datetime

# Fix Windows console encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/v1"

def test_health():
    """Test health endpoint"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print("[+] Health check passed")
            return True
        print(f"[-] Health check failed: {response.status_code}")
        return False
    except Exception as e:
        print(f"[-] Health check error: {e}")
        return False

def test_auth():
    """Test authentication"""
    try:
        response = requests.post(
            f"{API_URL}/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            token = data.get('access_token')
            print(f"[+] Authentication passed (token: {token[:20]}...)")
            return token
        print(f"[-] Authentication failed: {response.status_code}")
        return None
    except Exception as e:
        print(f"[-] Authentication error: {e}")
        return None

def test_satellites(token):
    """Test satellite listing"""
    try:
        response = requests.get(
            f"{API_URL}/satellites/list",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            count = len(data.get('satellites', []))
            print(f"[+] Satellites endpoint passed ({count} satellites)")
            return True
        print(f"[-] Satellites endpoint failed: {response.status_code}")
        return False
    except Exception as e:
        print(f"[-] Satellites error: {e}")
        return False

def test_modules(token):
    """Test module execution"""
    try:
        response = requests.post(
            f"{API_URL}/modules/execute",
            headers={"Authorization": f"Bearer {token}"},
            json={"command": "relay-status"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"[+] Module execution passed (module: {data.get('module')})")
                return True
        print(f"[-] Module execution failed")
        return False
    except Exception as e:
        print(f"[-] Module execution error: {e}")
        return False

def test_missions(token):
    """Test mission operations"""
    try:
        response = requests.get(
            f"{API_URL}/missions",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            count = len(data.get('missions', []))
            print(f"[+] Mission listing passed ({count} missions)")
            return True
        print(f"[-] Mission listing failed: {response.status_code}")
        return False
    except Exception as e:
        print(f"[-] Mission listing error: {e}")
        return False

def test_evidence(token):
    """Test evidence operations"""
    try:
        response = requests.get(
            f"{API_URL}/evidence",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        if response.status_code == 200:
            data = response.json()
            count = len(data.get('evidence', []))
            print(f"[+] Evidence listing passed ({count} items)")
            return True
        print(f"[-] Evidence listing failed: {response.status_code}")
        return False
    except Exception as e:
        print(f"[-] Evidence listing error: {e}")
        return False

def main():
    print("=" * 60)
    print("SPECTRE C2 BACKEND QUICK TEST")
    print("=" * 60)
    print()
    
    results = []
    
    # Test health
    results.append(("Health Check", test_health()))
    
    # Test authentication
    token = test_auth()
    results.append(("Authentication", token is not None))
    
    if token:
        # Test other endpoints
        results.append(("Satellites", test_satellites(token)))
        results.append(("Module Execution", test_modules(token)))
        results.append(("Missions", test_missions(token)))
        results.append(("Evidence", test_evidence(token)))
    
    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{name:30s} {status}")
    
    print()
    print(f"Results: {passed}/{total} passed ({int(passed/total*100)}%)")
    
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
