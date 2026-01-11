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
    print(f"[OK] Login successful")
    
    # Test modules list endpoint
    modules_url = "http://localhost:8000/api/v1/modules/list"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    modules_response = requests.get(modules_url, headers=headers)
    print(f"[OK] Modules list endpoint status: {modules_response.status_code}")
    modules_data = modules_response.json()
    print(f"[OK] Number of modules: {modules_data.get('total', 0)}")
    print(f"[OK] Categories: {', '.join(modules_data.get('categories', []))}")
    
    # Test execute module endpoint
    execute_url = "http://localhost:8000/api/v1/modules/execute"
    execute_payload = {
        "command": "enum-processes"
    }
    
    execute_response = requests.post(execute_url, json=execute_payload, headers=headers)
    print(f"\n[OK] Module execution status: {execute_response.status_code}")
    execute_data = execute_response.json()
    print(f"[OK] Execution result: {execute_data.get('success', False)}")
    print(f"[OK] Module: {execute_data.get('module', 'unknown')}")
    
except Exception as e:
    print(f"[ERROR] Error: {e}")
