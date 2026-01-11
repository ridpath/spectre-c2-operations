# -*- coding: utf-8 -*-
"""End-to-end user workflow test"""

import sys
import io
import requests
import time

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE_URL = "http://localhost:8000"
API_URL = f"{BASE_URL}/api/v1"

class WorkflowTester:
    def __init__(self):
        self.token = None
        self.user = None
        self.mission_id = None
        self.evidence_id = None
    
    def step(self, name, func):
        """Execute a test step"""
        print(f"\n{'='*60}")
        print(f"STEP: {name}")
        print('='*60)
        try:
            result = func()
            print(f"✅ PASSED")
            return result
        except Exception as e:
            print(f"❌ FAILED: {e}")
            raise
    
    def test_1_login(self):
        """Step 1: User logs in"""
        response = requests.post(
            f"{API_URL}/auth/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Login failed: {response.status_code}")
        
        data = response.json()
        self.token = data.get('access_token')
        self.user = data.get('user')
        
        print(f"  User: {self.user['username']}")
        print(f"  Role: {self.user['role']}")
        print(f"  Token: {self.token[:20]}...")
        return True
    
    def test_2_fetch_satellites(self):
        """Step 2: Fetch satellite list"""
        response = requests.get(
            f"{API_URL}/satellites/list?limit=10",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Satellite fetch failed: {response.status_code}")
        
        data = response.json()
        satellites = data.get('satellites', [])
        
        print(f"  Satellites loaded: {len(satellites)}")
        if satellites:
            print(f"  First satellite: {satellites[0]['name']}")
        return True
    
    def test_3_list_modules(self):
        """Step 3: List available modules"""
        response = requests.post(
            f"{API_URL}/modules/execute",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"command": "list-modules"},
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Module list failed: {response.status_code}")
        
        data = response.json()
        print(f"  Modules available: {data.get('count', 0)}")
        return True
    
    def test_4_create_mission(self):
        """Step 4: Create a new mission"""
        response = requests.post(
            f"{API_URL}/missions",
            headers={"Authorization": f"Bearer {self.token}"},
            json={
                "name": "Test Mission - Auto Workflow",
                "target_satellite": "ISS",
                "target_norad_id": 25544,
                "objective": "recon",
                "authorization": {
                    "hasPermission": True,
                    "documentPath": "/auth/test.pdf",
                    "authorizedBy": "admin",
                    "scope": ["recon"]
                }
            },
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Mission creation failed: {response.status_code}")
        
        data = response.json()
        self.mission_id = data.get('id')
        
        print(f"  Mission ID: {self.mission_id}")
        print(f"  Mission Name: {data.get('name')}")
        print(f"  Status: {data.get('status')}")
        return True
    
    def test_5_execute_module(self):
        """Step 5: Execute a tactical module"""
        response = requests.post(
            f"{API_URL}/modules/execute",
            headers={"Authorization": f"Bearer {self.token}"},
            json={
                "command": "relay-status",
                "mission_id": self.mission_id
            },
            timeout=10
        )
        
        if response.status_code != 200:
            raise Exception(f"Module execution failed: {response.status_code}")
        
        data = response.json()
        print(f"  Module: {data.get('module')}")
        print(f"  Success: {data.get('success')}")
        print(f"  Output length: {len(data.get('output', ''))} chars")
        return True
    
    def test_6_collect_evidence(self):
        """Step 6: Collect evidence"""
        response = requests.post(
            f"{API_URL}/evidence",
            headers={"Authorization": f"Bearer {self.token}"},
            json={
                "mission_id": self.mission_id,
                "category": "module_execution",
                "description": "Workflow test evidence",
                "data": "Test evidence data from automated workflow",
                "metadata": {
                    "source": "workflow_test",
                    "timestamp": time.time()
                }
            },
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Evidence collection failed: {response.status_code}")
        
        data = response.json()
        self.evidence_id = data.get('id')
        
        print(f"  Evidence ID: {self.evidence_id}")
        print(f"  Category: {data.get('category')}")
        return True
    
    def test_7_list_evidence(self):
        """Step 7: List collected evidence"""
        response = requests.get(
            f"{API_URL}/evidence",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Evidence listing failed: {response.status_code}")
        
        data = response.json()
        evidence_list = data.get('evidence', [])
        
        print(f"  Total evidence items: {len(evidence_list)}")
        return True
    
    def test_8_generate_payload(self):
        """Step 8: Generate a payload"""
        response = requests.post(
            f"{API_URL}/payloads/generate",
            headers={"Authorization": f"Bearer {self.token}"},
            json={
                "template_id": "powershell_reverse_tcp",
                "lhost": "10.10.14.12",
                "lport": 443,
                "arch": "x64",
                "encode": False
            },
            timeout=10
        )
        
        if response.status_code != 200:
            raise Exception(f"Payload generation failed: {response.status_code}")
        
        data = response.json()
        print(f"  Payload ID: {data.get('payload_id')}")
        print(f"  Template: {data.get('template')}")
        print(f"  Size: {data.get('size_bytes')} bytes")
        print(f"  Generator: {data.get('generator')}")
        return True
    
    def test_9_update_mission(self):
        """Step 9: Update mission status"""
        response = requests.put(
            f"{API_URL}/missions/{self.mission_id}",
            headers={"Authorization": f"Bearer {self.token}"},
            json={
                "status": "completed"
            },
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Mission update failed: {response.status_code}")
        
        data = response.json()
        print(f"  Mission status: {data.get('status')}")
        return True
    
    def test_10_audit_logs(self):
        """Step 10: Check audit logs"""
        response = requests.get(
            f"{API_URL}/opsec/logs?limit=10",
            headers={"Authorization": f"Bearer {self.token}"},
            timeout=5
        )
        
        if response.status_code != 200:
            raise Exception(f"Audit log fetch failed: {response.status_code}")
        
        data = response.json()
        logs = data.get('logs', [])
        
        print(f"  Recent actions logged: {len(logs)}")
        if logs:
            print(f"  Latest: {logs[0].get('action')}")
        return True
    
    def run_workflow(self):
        """Run complete workflow test"""
        print("\n" + "="*60)
        print("END-TO-END USER WORKFLOW TEST")
        print("="*60)
        print("\nSimulating complete operator workflow:")
        print("Login → Satellites → Modules → Mission → Execute → Evidence → Payload → Audit")
        
        steps = [
            ("1. User Authentication", self.test_1_login),
            ("2. Fetch Satellite Data", self.test_2_fetch_satellites),
            ("3. List Tactical Modules", self.test_3_list_modules),
            ("4. Create Mission", self.test_4_create_mission),
            ("5. Execute Module", self.test_5_execute_module),
            ("6. Collect Evidence", self.test_6_collect_evidence),
            ("7. List Evidence", self.test_7_list_evidence),
            ("8. Generate Payload", self.test_8_generate_payload),
            ("9. Complete Mission", self.test_9_update_mission),
            ("10. Review Audit Logs", self.test_10_audit_logs),
        ]
        
        passed = 0
        failed = 0
        
        for name, func in steps:
            try:
                self.step(name, func)
                passed += 1
            except Exception as e:
                failed += 1
                print(f"\n⚠️ Workflow interrupted at step: {name}")
                break
        
        print("\n" + "="*60)
        print("WORKFLOW TEST SUMMARY")
        print("="*60)
        print(f"Steps completed: {passed}/{len(steps)}")
        print(f"Success rate: {int(passed/len(steps)*100)}%")
        
        if failed == 0:
            print("\n✅ COMPLETE WORKFLOW SUCCESSFUL")
            print("\nThe system successfully handled:")
            print("  ✓ User authentication")
            print("  ✓ Data retrieval (satellites, modules)")
            print("  ✓ Mission lifecycle (create → execute → complete)")
            print("  ✓ Evidence collection")
            print("  ✓ Payload generation")
            print("  ✓ Audit logging")
            print("\n🎯 System is FULLY OPERATIONAL for end-to-end operations")
        else:
            print(f"\n⚠️ Workflow stopped at step {passed + 1}")
        
        return failed == 0

def main():
    tester = WorkflowTester()
    success = tester.run_workflow()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nWorkflow test interrupted by user")
        sys.exit(1)
