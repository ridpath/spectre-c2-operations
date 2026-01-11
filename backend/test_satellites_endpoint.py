import requests
import json

# First login
login_url = "http://localhost:8000/api/v1/auth/login"
login_payload = {
    "username": "admin",
    "password": "admin123"
}

try:
    login_response = requests.post(login_url, json=login_payload)
    login_data = login_response.json()
    token = login_data.get("access_token")
    print(f"[OK] Login successful, got token: {token[:50]}...")
    
    # Now test satellites endpoint
    satellites_url = "http://localhost:8000/api/v1/satellites/list?limit=500"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    satellites_response = requests.get(satellites_url, headers=headers)
    print(f"\n[OK] Satellites endpoint status: {satellites_response.status_code}")
    satellites_data = satellites_response.json()
    print(f"[OK] Number of satellites: {len(satellites_data.get('satellites', []))}")
    
    if satellites_data.get('satellites'):
        print(f"[OK] First satellite: {satellites_data['satellites'][0].get('name', 'Unknown')}")
    
except Exception as e:
    print(f"[ERROR] Error: {e}")
