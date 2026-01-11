"""APT Orchestrator Service Tests"""

import sys
import io
import requests

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/v1"

def get_auth_token():
    """Helper to get authentication token"""
    response = requests.post(
        f"{API_URL}/auth/login",
        json={"username": "admin", "password": "admin123"},
        timeout=5
    )
    return response.json().get('access_token')

def test_list_apt_chains():
    """Test listing all APT chains"""
    token = get_auth_token()
    
    response = requests.get(
        f"{API_URL}/apt/chains",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5
    )
    
    if response.status_code != 200:
        return False, f"Failed with status {response.status_code}"
    
    data = response.json()
    chains = data.get('chains', [])
    total = data.get('total', 0)
    
    if total == 0:
        return False, "No chains returned"
    
    if not chains:
        return False, "Chains list is empty"
    
    first_chain = chains[0]
    required_fields = ['id', 'name', 'description', 'threat_actor', 'heat_level', 'steps_count']
    for field in required_fields:
        if field not in first_chain:
            return False, f"Missing required field: {field}"
    
    print(f"  Total chains: {total}")
    print(f"  First chain: {first_chain['name']}")
    print(f"  Threat actor: {first_chain['threat_actor']}")
    print(f"  Steps: {first_chain['steps_count']}")
    
    return True, "Success"

def test_get_chain_details():
    """Test getting specific chain details"""
    token = get_auth_token()
    
    chains_response = requests.get(
        f"{API_URL}/apt/chains",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5
    )
    
    if chains_response.status_code != 200:
        return False, "Failed to get chains list"
    
    chains = chains_response.json().get('chains', [])
    if not chains:
        return False, "No chains available"
    
    chain_id = chains[0]['id']
    
    response = requests.get(
        f"{API_URL}/apt/chains/{chain_id}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5
    )
    
    if response.status_code != 200:
        return False, f"Failed with status {response.status_code}"
    
    chain = response.json()
    
    if chain['id'] != chain_id:
        return False, "Chain ID mismatch"
    
    print(f"  Chain ID: {chain['id']}")
    print(f"  Chain name: {chain['name']}")
    print(f"  Heat level: {chain['heat_level']}")
    print(f"  Total steps: {len(chain['steps'])}")
    
    return True, "Success"

def test_get_invalid_chain():
    """Test getting non-existent chain (should return 404)"""
    token = get_auth_token()
    
    response = requests.get(
        f"{API_URL}/apt/chains/invalid-chain-id-12345",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5
    )
    
    if response.status_code != 404:
        return False, f"Expected 404, got {response.status_code}"
    
    print(f"  Correctly returned 404 for invalid chain")
    
    return True, "Success"

def test_apt_chain_execution():
    """Test executing an APT chain (dry-run mode)"""
    token = get_auth_token()
    
    chains_response = requests.get(
        f"{API_URL}/apt/chains",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5
    )
    
    if chains_response.status_code != 200:
        return False, "Failed to get chains list"
    
    chains = chains_response.json().get('chains', [])
    if not chains:
        return False, "No chains available"
    
    chain = chains[0]
    
    response = requests.post(
        f"{API_URL}/apt/execute",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "chain_id": chain['id'],
            "variables": {
                "dc_target": "192.168.1.10",
                "domain": "testdomain.local"
            },
            "pause_on_error": True
        },
        timeout=30
    )
    
    if response.status_code != 200:
        return False, f"Execution failed with status {response.status_code}"
    
    result = response.json()
    
    required_fields = ['execution_id', 'chain_id', 'chain_name', 'started_at', 'completed_steps', 'step_results']
    for field in required_fields:
        if field not in result:
            return False, f"Missing required field in result: {field}"
    
    print(f"  Execution ID: {result['execution_id']}")
    print(f"  Chain: {result['chain_name']}")
    print(f"  Completed steps: {result['completed_steps']}/{result['total_steps']}")
    print(f"  Success: {result.get('success', False)}")
    
    return True, "Success"

def test_execution_history():
    """Test getting execution history"""
    token = get_auth_token()
    
    response = requests.get(
        f"{API_URL}/apt/history?limit=5",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5
    )
    
    if response.status_code != 200:
        return False, f"Failed with status {response.status_code}"
    
    data = response.json()
    history = data.get('history', [])
    
    print(f"  Total executions: {data.get('total', 0)}")
    if history:
        print(f"  Most recent: {history[0].get('chain_name', 'Unknown')}")
        print(f"  Execution time: {history[0].get('started_at', 'Unknown')}")
    
    return True, "Success"

def test_authentication_required():
    """Test that endpoints require authentication"""
    response = requests.get(
        f"{API_URL}/apt/chains",
        timeout=5
    )
    
    if response.status_code not in [401, 403]:
        return False, f"Expected 401/403, got {response.status_code}"
    
    print(f"  Correctly requires authentication (status {response.status_code})")
    
    return True, "Success"

def main():
    print("="*70)
    print("APT ORCHESTRATOR SERVICE TESTS")
    print("="*70)
    
    tests = [
        ("Authentication Required", test_authentication_required),
        ("List APT Chains", test_list_apt_chains),
        ("Get Chain Details", test_get_chain_details),
        ("Get Invalid Chain", test_get_invalid_chain),
        ("Execute APT Chain", test_apt_chain_execution),
        ("Get Execution History", test_execution_history),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        print(f"\n{'='*70}")
        print(f"TEST: {name}")
        print('='*70)
        
        try:
            success, message = test_func()
            if success:
                print(f"✅ PASSED: {message}")
                passed += 1
            else:
                print(f"❌ FAILED: {message}")
                failed += 1
        except Exception as e:
            print(f"❌ FAILED: {str(e)}")
            failed += 1
    
    print(f"\n{'='*70}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print('='*70)
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    exit(main())
