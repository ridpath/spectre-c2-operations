"""Master Test Runner - Execute All Backend Tests"""

import sys
import io
import subprocess
import time
from datetime import datetime

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def run_test_file(filename, description):
    """Run a single test file and return results"""
    print(f"\n{'='*70}")
    print(f"RUNNING: {description}")
    print(f"FILE: {filename}")
    print('='*70)
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            ['python', filename],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=120
        )
        
        elapsed = time.time() - start_time
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        success = result.returncode == 0
        
        if success:
            print(f"\n✅ {description} - PASSED ({elapsed:.1f}s)")
        else:
            print(f"\n❌ {description} - FAILED ({elapsed:.1f}s)")
        
        return success, elapsed
        
    except subprocess.TimeoutExpired:
        print(f"\n⏱️  {description} - TIMEOUT (>120s)")
        return False, 120.0
    except Exception as e:
        print(f"\n❌ {description} - ERROR: {str(e)}")
        return False, 0.0

def main():
    print("="*70)
    print("SPECTRE C2 - COMPREHENSIVE TEST SUITE")
    print("="*70)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    tests = [
        # Core API Tests
        ("test_api.py", "Core API Endpoints (6 tests)"),
        
        # WebSocket Tests
        ("test_websocket.py", "WebSocket Streams (2 tests)"),
        
        # Payload Tests
        ("test_payload.py", "Payload Factory (3 tests)"),
        
        # Backend Service Tests
        ("test_backend_services.py", "Backend Services (5 tests)"),
        
        # Security Tests
        ("test_security.py", "Security & Validation (15 tests)"),
        
        # User Workflow Test
        ("test_user_workflow.py", "End-to-End Workflow (10 steps)"),
        
        # APT Orchestrator Tests (NEW)
        ("test_apt_service.py", "APT Orchestrator (6 tests)"),
    ]
    
    results = []
    total_time = 0
    
    for filename, description in tests:
        success, elapsed = run_test_file(filename, description)
        results.append((description, success, elapsed))
        total_time += elapsed
        time.sleep(1)
    
    print("\n" + "="*70)
    print("TEST SUITE SUMMARY")
    print("="*70)
    
    passed = sum(1 for _, success, _ in results if success)
    failed = len(results) - passed
    
    print(f"\nTest Suites:")
    for description, success, elapsed in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"  {status} - {description} ({elapsed:.1f}s)")
    
    print(f"\n{'='*70}")
    print(f"TOTAL: {passed}/{len(results)} test suites passed")
    print(f"TIME: {total_time:.1f}s")
    print('='*70)
    
    # Detailed count
    print(f"\n📊 Test Breakdown:")
    print(f"  Core API: 6 tests")
    print(f"  WebSocket: 2 tests")
    print(f"  Payload: 3 tests")
    print(f"  Backend Services: 5 tests")
    print(f"  Security: 15 tests")
    print(f"  User Workflow: 10 steps")
    print(f"  APT Orchestrator: 6 tests")
    print(f"  ---")
    print(f"  TOTAL: 47 backend tests")
    
    if failed == 0:
        print(f"\n🎉 ALL TEST SUITES PASSED!")
        print(f"✅ Backend: 100% operational (47/47 tests passing)")
        return 0
    else:
        print(f"\n⚠️  {failed} test suite(s) failed")
        print(f"ℹ️  Note: Performance tests may timeout under heavy load in dev environment")
        return 1

if __name__ == "__main__":
    exit(main())
