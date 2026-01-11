#!/usr/bin/env python3
"""
Backend Integration Test Script
Tests all major backend endpoints and services
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/v1"

def print_test(name):
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print('='*60)

def print_success(msg):
    print(f"[+] {msg}")

def print_error(msg):
    print(f"[-] {msg}")

def test_health():
    print_test("Health Check")
    try:
        response = requests.get(f"{BASE_URL}/health")
        data = response.json()
        print_success(f"Backend responding: {data['app']} v{data['version']}")
        print_success(f"Status: {data['status']}")
        return True
    except Exception as e:
        print_error(f"Health check failed: {e}")
        return False

def test_auth():
    print_test("Authentication")
    try:
        response = requests.post(
            f"{API_URL}/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        data = response.json()
        
        if response.status_code == 200:
            print_success(f"Login successful")
            print_success(f"User: {data['user']['username']} ({data['user']['role']})")
            token = data['access_token']
            print_success(f"Token received: {token[:20]}...")
            return token
        else:
            print_error(f"Login failed: {data}")
            return None
    except Exception as e:
        print_error(f"Auth test failed: {e}")
        return None

def test_satellites(token):
    print_test("Satellite Database")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/satellites/list", headers=headers)
        data = response.json()
        
        if response.status_code == 200:
            satellites = data.get('satellites', [])
            print_success(f"Found {len(satellites)} satellites")
            for sat in satellites[:3]:
                print(f"  - {sat['satellite_name']} (NORAD: {sat['norad_id']})")
            return True
        else:
            print_error(f"Satellite fetch failed: {data}")
            return False
    except Exception as e:
        print_error(f"Satellite test failed: {e}")
        return False

def test_module_execution(token):
    print_test("Module Execution")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        
        test_command = "relay-status"
        response = requests.post(
            f"{API_URL}/modules/execute",
            headers=headers,
            json={"command": test_command}
        )
        data = response.json()
        
        if response.status_code == 200:
            if data.get('success'):
                print_success(f"Module '{data.get('module')}' executed")
                print_success(f"Execution ID: {data.get('execution_id')}")
                if data.get('output'):
                    print(f"Output: {data['output'][:100]}...")
            else:
                print_error(f"Module execution failed: {data.get('error')}")
                print(f"Error type: {data.get('error_type')}")
            return data.get('success', False)
        else:
            print_error(f"Request failed: {data}")
            return False
    except Exception as e:
        print_error(f"Module execution test failed: {e}")
        return False

def test_module_list(token):
    print_test("Module Listing")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/modules/list", headers=headers)
        data = response.json()
        
        if response.status_code == 200:
            modules = data.get('modules', [])
            categories = data.get('categories', [])
            print_success(f"Found {data.get('total')} modules")
            print_success(f"Categories: {', '.join(categories)}")
            
            print("\nSample modules:")
            for cat in categories[:2]:
                cat_modules = [m for m in modules if m['category'] == cat]
                print(f"\n  {cat.upper()}:")
                for mod in cat_modules[:3]:
                    print(f"    - {mod['name']}: {mod['description'][:50]}...")
            return True
        else:
            print_error(f"Module list failed: {data}")
            return False
    except Exception as e:
        print_error(f"Module list test failed: {e}")
        return False

def test_apt_chains(token):
    print_test("APT Tactical Chains")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/apt/chains", headers=headers)
        data = response.json()
        
        if response.status_code == 200:
            chains = data.get('chains', [])
            print_success(f"Found {data.get('total')} APT chains")
            for chain in chains:
                print(f"\n  {chain['name']}:")
                print(f"    ID: {chain['id']}")
                print(f"    Threat Actor: {chain['threat_actor_mimicry']}")
                print(f"    Heat Level: {chain['heat_level']}/100")
                print(f"    Steps: {chain['total_steps']}")
            return True
        else:
            print_error(f"APT chains failed: {data}")
            return False
    except Exception as e:
        print_error(f"APT chains test failed: {e}")
        return False

def test_missions(token):
    print_test("Mission Management")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/missions", headers=headers)
        data = response.json()
        
        if response.status_code == 200:
            missions = data.get('missions', [])
            print_success(f"Found {len(missions)} missions")
            if missions:
                for mission in missions[:3]:
                    print(f"  - {mission['name']} ({mission['status']})")
            else:
                print("  No missions created yet")
            return True
        else:
            print_error(f"Mission fetch failed: {data}")
            return False
    except Exception as e:
        print_error(f"Mission test failed: {e}")
        return False

def test_vulnerabilities(token):
    print_test("Vulnerability Scanner")
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_URL}/vulnerabilities", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            print_success(f"Found {len(vulns)} vulnerabilities in database")
            return True
        else:
            print_error(f"Vulnerability fetch failed")
            return False
    except Exception as e:
        print_error(f"Vulnerability test failed: {e}")
        return False

def main():
    print("\n" + "="*60)
    print(" SPECTRE C2 BACKEND INTEGRATION TEST SUITE")
    print("="*60)
    
    results = {}
    
    if not test_health():
        print("\n" + "="*60)
        print("FATAL: Backend not responding on http://localhost:8000")
        print("Start backend with: cd backend && python backend.py")
        print("="*60)
        return
    
    token = test_auth()
    if not token:
        print("\n" + "="*60)
        print("FATAL: Authentication failed")
        print("Ensure database is initialized: cd backend && python init_db_sqlite.py")
        print("="*60)
        return
    
    results['Satellites'] = test_satellites(token)
    results['Module List'] = test_module_list(token)
    results['Module Execute'] = test_module_execution(token)
    results['APT Chains'] = test_apt_chains(token)
    results['Missions'] = test_missions(token)
    results['Vulnerabilities'] = test_vulnerabilities(token)
    
    print("\n" + "="*60)
    print(" TEST RESULTS SUMMARY")
    print("="*60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"{test_name:20s} ... {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed ({100*passed//total}%)")
    
    if passed == total:
        print("\n[SUCCESS] All backend integrations working correctly!")
    else:
        print("\n[WARNING] Some integrations need attention")
    
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
