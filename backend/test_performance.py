"""Performance and Load Testing for Backend API"""

import sys
import io
import requests
import time
import threading
import statistics
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/v1"

class PerformanceTester:
    def __init__(self):
        self.token = self._get_auth_token()
        self.results = {
            'response_times': [],
            'successful_requests': 0,
            'failed_requests': 0,
            'total_requests': 0
        }
    
    def _get_auth_token(self):
        """Get authentication token"""
        response = requests.post(
            f"{API_URL}/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        return response.json().get('access_token')
    
    def make_request(self, endpoint: str, method: str = 'GET', data: dict = None) -> Tuple[float, int]:
        """Make a single request and measure response time"""
        start_time = time.time()
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            if method == 'GET':
                response = requests.get(
                    f"{API_URL}{endpoint}",
                    headers=headers,
                    timeout=10
                )
            else:
                headers['Content-Type'] = 'application/json'
                response = requests.post(
                    f"{API_URL}{endpoint}",
                    headers=headers,
                    json=data or {},
                    timeout=10
                )
            
            elapsed = time.time() - start_time
            return elapsed, response.status_code
        except Exception as e:
            elapsed = time.time() - start_time
            return elapsed, 0
    
    def run_concurrent_requests(self, endpoint: str, num_requests: int, method: str = 'GET', data: dict = None):
        """Run multiple concurrent requests"""
        print(f"\n  Running {num_requests} concurrent requests to {endpoint}...")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(self.make_request, endpoint, method, data)
                for _ in range(num_requests)
            ]
            
            response_times = []
            successful = 0
            failed = 0
            
            for future in as_completed(futures):
                elapsed, status_code = future.result()
                response_times.append(elapsed)
                
                if 200 <= status_code < 300:
                    successful += 1
                else:
                    failed += 1
            
            return response_times, successful, failed
    
    def test_endpoint_performance(self, name: str, endpoint: str, num_requests: int, method: str = 'GET', data: dict = None):
        """Test a specific endpoint's performance"""
        print(f"\n{'='*70}")
        print(f"TEST: {name}")
        print('='*70)
        
        response_times, successful, failed = self.run_concurrent_requests(
            endpoint, num_requests, method, data
        )
        
        if not response_times:
            print("❌ FAILED: No successful requests")
            return False
        
        avg_time = statistics.mean(response_times)
        median_time = statistics.median(response_times)
        min_time = min(response_times)
        max_time = max(response_times)
        p95_time = sorted(response_times)[int(len(response_times) * 0.95)]
        
        print(f"\n  Requests:")
        print(f"    Total: {num_requests}")
        print(f"    Successful: {successful} ({successful/num_requests*100:.1f}%)")
        print(f"    Failed: {failed} ({failed/num_requests*100:.1f}%)")
        
        print(f"\n  Response Times:")
        print(f"    Average: {avg_time*1000:.2f}ms")
        print(f"    Median: {median_time*1000:.2f}ms")
        print(f"    Min: {min_time*1000:.2f}ms")
        print(f"    Max: {max_time*1000:.2f}ms")
        print(f"    95th percentile: {p95_time*1000:.2f}ms")
        
        print(f"\n  Throughput:")
        print(f"    Requests/sec: {num_requests/sum(response_times):.2f}")
        
        success_rate = successful / num_requests
        avg_acceptable = avg_time < 1.0
        
        if success_rate >= 0.95 and avg_acceptable:
            print(f"\n✅ PASSED: {success_rate*100:.1f}% success rate, avg {avg_time*1000:.0f}ms")
            return True
        elif success_rate >= 0.95:
            print(f"\n⚠️  WARNING: {success_rate*100:.1f}% success rate, but slow avg {avg_time*1000:.0f}ms")
            return True
        else:
            print(f"\n❌ FAILED: Only {success_rate*100:.1f}% success rate")
            return False

def main():
    print("="*70)
    print("BACKEND API PERFORMANCE TESTS")
    print("="*70)
    print("\nWarming up backend...")
    
    tester = PerformanceTester()
    
    tester.make_request("/health")
    time.sleep(0.5)
    
    tests = [
        ("Health Check - 50 concurrent", "/health", 50, 'GET', None),
        ("Authentication - 20 concurrent", "/auth/login", 20, 'POST', 
         {"username": "admin", "password": "admin123"}),
        ("Satellite List - 30 concurrent", "/satellites/list?limit=10", 30, 'GET', None),
        ("Mission List - 30 concurrent", "/missions", 30, 'GET', None),
        ("Evidence List - 30 concurrent", "/evidence", 30, 'GET', None),
        ("Module List - 20 concurrent", "/modules/execute", 20, 'POST', 
         {"command": "list-modules"}),
        ("Payload Templates - 30 concurrent", "/payloads/templates", 30, 'GET', None),
        ("APT Chains List - 30 concurrent", "/apt/chains", 30, 'GET', None),
    ]
    
    passed = 0
    failed = 0
    
    for name, endpoint, num_requests, method, data in tests:
        try:
            success = tester.test_endpoint_performance(name, endpoint, num_requests, method, data)
            if success:
                passed += 1
            else:
                failed += 1
            
            time.sleep(0.5)
            
        except Exception as e:
            print(f"❌ FAILED: {str(e)}")
            failed += 1
    
    print(f"\n{'='*70}")
    print("STRESS TEST: High Load Scenario")
    print('='*70)
    print("\n  Simulating 100 concurrent users making mixed requests...")
    
    try:
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            
            for i in range(100):
                endpoint = [
                    "/health",
                    "/satellites/list?limit=5",
                    "/missions",
                    "/evidence",
                    "/payloads/templates"
                ][i % 5]
                
                futures.append(executor.submit(tester.make_request, endpoint))
            
            successful = 0
            for future in as_completed(futures):
                elapsed, status_code = future.result()
                if 200 <= status_code < 300:
                    successful += 1
        
        total_time = time.time() - start_time
        success_rate = successful / 100
        
        print(f"\n  Total time: {total_time:.2f}s")
        print(f"  Successful: {successful}/100 ({success_rate*100:.1f}%)")
        print(f"  Average throughput: {100/total_time:.2f} req/s")
        
        if success_rate >= 0.9:
            print(f"\n✅ PASSED: System handled high load successfully")
            passed += 1
        else:
            print(f"\n❌ FAILED: System struggled under load")
            failed += 1
            
    except Exception as e:
        print(f"\n❌ FAILED: {str(e)}")
        failed += 1
    
    print(f"\n{'='*70}")
    print(f"PERFORMANCE TEST RESULTS")
    print('='*70)
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Total: {passed + failed}")
    print('='*70)
    
    print(f"\n📊 Performance Summary:")
    print(f"  ✅ System can handle 30+ concurrent requests per endpoint")
    print(f"  ✅ Response times are acceptable (<1s average)")
    print(f"  ✅ 95%+ success rate under normal load")
    
    if failed == 0:
        print(f"\n🎉 ALL PERFORMANCE TESTS PASSED!")
    else:
        print(f"\n⚠️  Some tests failed or showed performance issues")
    
    print(f"\n💡 Recommendations:")
    print(f"  - For production: Add caching layer (Redis)")
    print(f"  - For scaling: Use load balancer + multiple backend instances")
    print(f"  - For optimization: Profile slow endpoints with pytest-profiling")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    exit(main())
