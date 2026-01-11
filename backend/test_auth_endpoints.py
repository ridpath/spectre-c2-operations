#!/usr/bin/env python3
import requests
import json

BASE_URL = "http://localhost:8000"

print("=" * 70)
print("Testing Backend Authentication and Endpoints")
print("=" * 70)

# Test 1: Login
print("\n1. Testing login endpoint...")
login_data = {"username": "admin", "password": "admin123"}
try:
    response = requests.post(f"{BASE_URL}/api/v1/auth/login", json=login_data)
    print(f"   Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        token = data.get("access_token")
        print(f"   SUCCESS: Got access token: {token[:30]}...")
        
        # Test 2: Get missions
        print("\n2. Testing /api/v1/missions endpoint...")
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{BASE_URL}/api/v1/missions", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   SUCCESS: {response.json()}")
        else:
            print(f"   FAILED: {response.text}")
        
        # Test 3: Get vulnerabilities
        print("\n3. Testing /api/v1/vulnerabilities endpoint...")
        response = requests.get(f"{BASE_URL}/api/v1/vulnerabilities", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   SUCCESS: Got vulnerabilities")
        else:
            print(f"   FAILED: {response.text}")
        
        # Test 4: Scan vulnerabilities
        print("\n4. Testing /api/v1/vulnerabilities/scan endpoint...")
        scan_data = {"satellite_name": "TEST-SAT-1", "target_systems": ["TTC", "CDH"]}
        response = requests.post(f"{BASE_URL}/api/v1/vulnerabilities/scan", headers=headers, json=scan_data)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print(f"   SUCCESS: Scan completed")
        else:
            print(f"   FAILED: {response.text}")
        
        # Test 5: Get satellites
        print("\n5. Testing /api/v1/satellites/list endpoint...")
        response = requests.get(f"{BASE_URL}/api/v1/satellites/list?limit=10", headers=headers)
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            print(f"   SUCCESS: Found {len(data.get('satellites', []))} satellites")
        else:
            print(f"   FAILED: {response.text}")
        
    else:
        print(f"   FAILED: {response.text}")
except Exception as e:
    print(f"   ERROR: {e}")

print("\n" + "=" * 70)
