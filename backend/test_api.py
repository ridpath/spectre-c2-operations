import requests

# First login to get token
login_url = "http://localhost:8000/api/v1/auth/login"
login_data = {
    "username": "admin",
    "password": "admin123"
}

print("Logging in...")
response = requests.post(login_url, json=login_data)
print(f"Login status: {response.status_code}")

if response.status_code == 200:
    data = response.json()
    token = data.get('access_token')
    print(f"Got token: {token[:20]}...")
    
    # Now test satellite list
    print("\nFetching satellite list...")
    sat_url = "http://localhost:8000/api/v1/satellites/list?limit=5"
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    sat_response = requests.get(sat_url, headers=headers)
    print(f"Satellite list status: {sat_response.status_code}")
    
    if sat_response.status_code == 200:
        sat_data = sat_response.json()
        print(f"Total satellites: {sat_data['total']}")
        print(f"Returned: {len(sat_data['satellites'])} satellites")
        for sat in sat_data['satellites'][:3]:
            print(f"  - {sat['name']} (NORAD {sat['norad_id']})")
    else:
        print(f"Error: {sat_response.text}")
else:
    print(f"Login failed: {response.text}")
