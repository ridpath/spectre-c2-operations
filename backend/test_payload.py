# -*- coding: utf-8 -*-
"""Payload factory endpoint tests"""

import sys
import io
import requests

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/v1"

def test_payload_templates():
    """Test payload templates endpoint"""
    try:
        response = requests.post(
            f"{API_URL}/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        token = response.json().get('access_token')
        
        response = requests.get(
            f"{API_URL}/payloads/templates",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            templates = data.get('templates', [])
            formats = data.get('formats', [])
            print(f"[+] Payload templates: {len(templates)} templates, {len(formats)} formats")
            for template in templates:
                print(f"    - {template['name']} ({template['format']}) - {template['evasion_level']} evasion")
            return True
        else:
            print(f"[-] Payload templates failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def test_payload_generation():
    """Test payload generation"""
    try:
        response = requests.post(
            f"{API_URL}/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        token = response.json().get('access_token')
        
        response = requests.post(
            f"{API_URL}/payloads/generate",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "template_id": "powershell_reverse_tcp",
                "lhost": "10.10.14.12",
                "lport": 443,
                "arch": "x64",
                "encode": False
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"[+] Payload generation successful:")
                print(f"    - Template: {data.get('template')}")
                print(f"    - Format: {data.get('format')}")
                print(f"    - Size: {data.get('size_bytes')} bytes")
                print(f"    - Generator: {data.get('generator')}")
                if data.get('warning'):
                    print(f"    - Warning: {data.get('warning')}")
                return True
            else:
                print(f"[-] Payload generation failed: {data.get('error')}")
                return False
        else:
            print(f"[-] Payload generation request failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def test_dropper_generation():
    """Test custom dropper generation"""
    try:
        response = requests.post(
            f"{API_URL}/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        token = response.json().get('access_token')
        
        response = requests.post(
            f"{API_URL}/payloads/dropper",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "payload_type": "powershell",
                "lhost": "10.10.14.12",
                "lport": 443,
                "evasion_features": ["amsi_bypass", "etw_patch", "sleep_masking"],
                "delivery_method": "direct"
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                print(f"[+] Dropper generation successful:")
                print(f"    - Dropper ID: {data.get('dropper_id')}")
                print(f"    - Type: {data.get('type')}")
                print(f"    - Features: {', '.join(data.get('evasion_features', []))}")
                print(f"    - Size: {data.get('size_bytes')} bytes")
                return True
            else:
                print(f"[-] Dropper generation failed: {data.get('error')}")
                return False
        else:
            print(f"[-] Dropper generation request failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

def main():
    print("="*60)
    print("PAYLOAD FACTORY ENDPOINT TESTS")
    print("="*60)
    
    results = []
    
    print("\n[1/3] Testing payload templates...")
    results.append(test_payload_templates())
    
    print("\n[2/3] Testing payload generation...")
    results.append(test_payload_generation())
    
    print("\n[3/3] Testing dropper generation...")
    results.append(test_dropper_generation())
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Results: {passed}/{total} passed ({int(passed/total*100)}%)")
    
    if passed == total:
        print("\n✅ All payload factory tests PASSED")
    else:
        print("\n⚠️ Some tests failed")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
