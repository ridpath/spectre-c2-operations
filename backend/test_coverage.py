#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprehensive API endpoint coverage test"""

import sys
import io
import requests
import json
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/v1"

def get_token():
    """Get authentication token"""
    response = requests.post(
        f"{API_URL}/auth/login",
        json={"username": "admin", "password": "admin123"},
        timeout=5
    )
    return response.json().get('access_token')

def test_endpoint(method, endpoint, token=None, data=None, description=""):
    """Test a single endpoint"""
    headers = {}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    
    try:
        if method == 'GET':
            response = requests.get(f"{API_URL}{endpoint}", headers=headers, timeout=3)
        elif method == 'POST':
            response = requests.post(f"{API_URL}{endpoint}", headers=headers, json=data or {}, timeout=3)
        elif method == 'PUT':
            response = requests.put(f"{API_URL}{endpoint}", headers=headers, json=data or {}, timeout=3)
        elif method == 'DELETE':
            response = requests.delete(f"{API_URL}{endpoint}", headers=headers, timeout=3)
        
        status = "PASS" if response.status_code < 400 else "FAIL"
        print(f"[{status}] {method:6} {endpoint:40} {response.status_code}")
        return response.status_code < 400
    except requests.Timeout:
        print(f"[TIMEOUT] {method:6} {endpoint:40} >3s")
        return False
    except Exception as e:
        print(f"[ERROR] {method:6} {endpoint:40} {str(e)[:30]}")
        return False

def main():
    print("="*80)
    print("COMPREHENSIVE API ENDPOINT COVERAGE TEST")
    print("="*80)
    print()
    
    # Get auth token
    print("[INFO] Authenticating...")
    token = get_token()
    print(f"[INFO] Token obtained: {token[:20]}...\n")
    
    results = []
    
    # Core endpoints
    print("--- Core Endpoints ---")
    results.append(test_endpoint('GET', '/health', token=None))
    results.append(test_endpoint('POST', '/auth/login', token=None, data={"username": "admin", "password": "admin123"}))
    results.append(test_endpoint('GET', '/users/me', token=token))
    
    # Satellite endpoints
    print("\n--- Satellite Endpoints ---")
    results.append(test_endpoint('GET', '/satellites/list', token=token))
    results.append(test_endpoint('GET', '/satellites/tle', token=token))
    results.append(test_endpoint('POST', '/satellites/predict', token=token, data={"norad_id": 25544, "observer_lat": 0, "observer_lon": 0, "observer_alt": 0}))
    
    # C2 endpoints
    print("\n--- C2 Endpoints ---")
    results.append(test_endpoint('GET', '/c2/agents', token=token))
    results.append(test_endpoint('GET', '/c2/tasks', token=token))
    
    # Module endpoints
    print("\n--- Module Endpoints ---")
    results.append(test_endpoint('GET', '/modules/list', token=token))
    results.append(test_endpoint('POST', '/modules/execute', token=token, data={"module_id": "relay-status", "target": "localhost"}))
    
    # Mission endpoints
    print("\n--- Mission Endpoints ---")
    results.append(test_endpoint('GET', '/missions', token=token))
    
    # Evidence endpoints
    print("\n--- Evidence Endpoints ---")
    results.append(test_endpoint('GET', '/evidence', token=token))
    
    # OpSec endpoints
    print("\n--- OpSec Endpoints ---")
    results.append(test_endpoint('GET', '/opsec/logs', token=token))
    results.append(test_endpoint('GET', '/tor/status', token=token))
    
    # Playbook endpoints
    print("\n--- Playbook Endpoints ---")
    results.append(test_endpoint('GET', '/playbooks', token=token))
    
    # Template endpoints
    print("\n--- Template Endpoints ---")
    results.append(test_endpoint('GET', '/templates', token=token))
    
    # Report endpoints
    print("\n--- Report Endpoints ---")
    results.append(test_endpoint('GET', '/reports', token=token))
    
    # Relay/Pivot endpoints
    print("\n--- Relay/Pivot Endpoints ---")
    results.append(test_endpoint('GET', '/pivot/tunnels', token=token))
    results.append(test_endpoint('GET', '/ligolo/tunnels', token=token))
    
    # APT endpoints
    print("\n--- APT Endpoints ---")
    results.append(test_endpoint('GET', '/apt/chains', token=token))
    
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    passed = sum(results)
    total = len(results)
    percentage = int(passed/total*100) if total > 0 else 0
    print(f"Results: {passed}/{total} passed ({percentage}%)")
    print(f"Status: {'✓ ALL TESTS PASSED' if passed == total else '✗ SOME TESTS FAILED'}")

if __name__ == "__main__":
    main()
