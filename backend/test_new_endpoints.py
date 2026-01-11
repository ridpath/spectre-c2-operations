import requests
import json

BASE_URL = "http://localhost:8000/api/v1"
AUTH_TOKEN = "valid_token"
HEADERS = {
    "Authorization": f"Bearer {AUTH_TOKEN}",
    "Content-Type": "application/json"
}

def test_vulnerabilities():
    print("=" * 60)
    print("Testing Vulnerabilities Endpoints")
    print("=" * 60)
    
    response = requests.get(f"{BASE_URL}/vulnerabilities", headers=HEADERS)
    print(f"GET /vulnerabilities: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}\n")
    
    scan_data = {"norad_id": 43105, "satellite_name": "STERN-WATCH-4"}
    response = requests.post(f"{BASE_URL}/vulnerabilities/scan", headers=HEADERS, json=scan_data)
    print(f"POST /vulnerabilities/scan: {response.status_code}")
    print(f"Found {len(response.json().get('vulnerabilities', []))} vulnerabilities\n")

def test_missions():
    print("=" * 60)
    print("Testing Missions Endpoints")
    print("=" * 60)
    
    response = requests.get(f"{BASE_URL}/missions", headers=HEADERS)
    print(f"GET /missions: {response.status_code}")
    print(f"Current missions: {len(response.json().get('missions', []))}\n")
    
    mission_data = {
        "name": "Test Mission",
        "target_satellite": "ISS",
        "target_norad_id": 25544,
        "objective": "recon",
        "authorization": {"hasPermission": True, "scope": ["recon"]}
    }
    response = requests.post(f"{BASE_URL}/missions", headers=HEADERS, json=mission_data)
    print(f"POST /missions: {response.status_code}")
    if response.ok:
        mission = response.json()
        print(f"Created mission: {mission['name']} (ID: {mission['id']})\n")
        return mission['id']
    return None

def test_evidence(mission_id):
    print("=" * 60)
    print("Testing Evidence Endpoints")
    print("=" * 60)
    
    response = requests.get(f"{BASE_URL}/evidence", headers=HEADERS)
    print(f"GET /evidence: {response.status_code}")
    print(f"Total evidence items: {len(response.json().get('evidence', []))}\n")
    
    evidence_data = {
        "mission_id": mission_id or "test-mission",
        "category": "command_output",
        "description": "Test evidence",
        "data": "echo test",
        "metadata": {},
        "tags": ["test"]
    }
    response = requests.post(f"{BASE_URL}/evidence", headers=HEADERS, json=evidence_data)
    print(f"POST /evidence: {response.status_code}")
    if response.ok:
        print(f"Created evidence: {response.json()['id']}\n")

def test_reports(mission_id):
    print("=" * 60)
    print("Testing Reports Endpoints")
    print("=" * 60)
    
    if not mission_id:
        print("Skipping (no mission ID)\n")
        return
    
    report_data = {
        "mission_id": mission_id,
        "format": "markdown"
    }
    response = requests.post(f"{BASE_URL}/reports/generate", headers=HEADERS, json=report_data)
    print(f"POST /reports/generate: {response.status_code}")
    if response.ok:
        report = response.json()
        print(f"Generated report (ID: {report['id']})")
        print(f"Report length: {len(report.get('content', ''))} characters\n")
    
    response = requests.get(f"{BASE_URL}/reports", headers=HEADERS)
    print(f"GET /reports: {response.status_code}")
    print(f"Total reports: {len(response.json().get('reports', []))}\n")

def test_passes():
    print("=" * 60)
    print("Testing Pass Prediction Endpoint")
    print("=" * 60)
    
    params = {
        "norad_id": 43105,
        "latitude": 37.7749,
        "longitude": -122.4194,
        "altitude": 0,
        "min_elevation": 10,
        "hours_ahead": 24
    }
    response = requests.get(f"{BASE_URL}/passes/predict", params=params, headers=HEADERS)
    print(f"GET /passes/predict: {response.status_code}")
    if response.ok:
        data = response.json()
        print(f"Satellite: {data['satellite']}")
        print(f"Predicted passes: {len(data['passes'])}\n")

def test_safety():
    print("=" * 60)
    print("Testing Safety Check Endpoint")
    print("=" * 60)
    
    check_data = {
        "frequency": 437.5,
        "power": 50,
        "modulation": "BPSK",
        "target_satellite": "ISS"
    }
    response = requests.post(f"{BASE_URL}/safety/check", headers=HEADERS, json=check_data)
    print(f"POST /safety/check: {response.status_code}")
    if response.ok:
        data = response.json()
        print(f"Approved: {data['approved']}")
        print(f"Checks passed: {sum(1 for c in data['checks'] if c['passed'])}/{len(data['checks'])}\n")

def test_templates():
    print("=" * 60)
    print("Testing Templates Endpoints")
    print("=" * 60)
    
    response = requests.get(f"{BASE_URL}/templates", headers=HEADERS)
    print(f"GET /templates: {response.status_code}")
    print(f"Total templates: {len(response.json().get('templates', []))}\n")

def main():
    print("\n" + "=" * 60)
    print("BACKEND INTEGRATION TEST SUITE")
    print("=" * 60 + "\n")
    
    try:
        test_vulnerabilities()
        mission_id = test_missions()
        test_evidence(mission_id)
        test_reports(mission_id)
        test_passes()
        test_safety()
        test_templates()
        
        print("=" * 60)
        print("✓ ALL TESTS COMPLETED SUCCESSFULLY")
        print("=" * 60)
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")

if __name__ == "__main__":
    main()
