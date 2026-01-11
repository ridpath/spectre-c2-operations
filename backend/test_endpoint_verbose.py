import requests
import json

# Login
login_url = "http://localhost:8000/api/v1/auth/login"
login_data = {"username": "admin", "password": "admin123"}

print("=== LOGIN ===")
try:
    response = requests.post(login_url, json=login_data, timeout=5)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        token = data.get('access_token')
        print(f"Token obtained: {token[:30]}...")
    else:
        print(f"Response: {response.text}")
        exit(1)
except Exception as e:
    print(f"Login error: {e}")
    exit(1)

# Test satellite list
print("\n=== SATELLITE LIST ===")
sat_url = "http://localhost:8000/api/v1/satellites/list?limit=5"
headers = {"Authorization": f"Bearer {token}"}

try:
    sat_response = requests.get(sat_url, headers=headers, timeout=10)
    print(f"Status: {sat_response.status_code}")
    print(f"Headers: {dict(sat_response.headers)}")
    print(f"Content-Type: {sat_response.headers.get('content-type')}")
    
    if sat_response.status_code == 200:
        data = sat_response.json()
        print(f"Success! Total: {data.get('total')}")
        print(f"Satellites returned: {len(data.get('satellites', []))}")
    else:
        print(f"Error body: {sat_response.text[:500]}")
        
except Exception as e:
    print(f"Request error: {e}")
    import traceback
    traceback.print_exc()
