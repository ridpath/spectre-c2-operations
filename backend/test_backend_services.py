# -*- coding: utf-8 -*-
"""Backend service unit tests"""

import sys
import io
import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import uuid

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

from payload_factory import PayloadFactory

class TestPayloadFactory(unittest.TestCase):
    """Test PayloadFactory class"""
    
    def setUp(self):
        self.factory = PayloadFactory()
    
    def test_list_templates(self):
        """Test template listing"""
        templates = self.factory.list_templates()
        self.assertIsInstance(templates, list)
        self.assertGreater(len(templates), 0)
        
        for template in templates:
            self.assertIn('id', template)
            self.assertIn('name', template)
            self.assertIn('description', template)
            self.assertIn('format', template)
            self.assertIn('evasion_level', template)
    
    def test_get_formats(self):
        """Test format listing"""
        formats = self.factory.get_formats()
        self.assertIsInstance(formats, list)
        self.assertIn('powershell', formats)
        self.assertIn('exe', formats)
        self.assertIn('dll', formats)
    
    def test_mock_payload_generation(self):
        """Test mock payload generation (no msfvenom)"""
        import asyncio
        
        async def run_test():
            result = await self.factory.generate_payload(
                template_id='powershell_reverse_tcp',
                lhost='10.10.14.12',
                lport=443,
                arch='x64',
                encode=False
            )
            
            self.assertTrue(result.get('success'))
            self.assertEqual(result.get('lhost'), '10.10.14.12')
            self.assertEqual(result.get('lport'), 443)
            self.assertIn('content', result)
            self.assertIn('payload_id', result)
        
        asyncio.run(run_test())
    
    def test_invalid_template(self):
        """Test invalid template handling"""
        import asyncio
        
        async def run_test():
            result = await self.factory.generate_payload(
                template_id='invalid_template',
                lhost='10.10.14.12',
                lport=443
            )
            
            self.assertFalse(result.get('success'))
            self.assertIn('error', result)
        
        asyncio.run(run_test())
    
    def test_custom_dropper(self):
        """Test custom dropper generation"""
        import asyncio
        
        async def run_test():
            result = await self.factory.generate_custom_dropper(
                payload_type='powershell',
                lhost='10.10.14.12',
                lport=443,
                evasion_features=['amsi_bypass', 'etw_patch'],
                delivery_method='direct'
            )
            
            self.assertTrue(result.get('success'))
            self.assertIn('dropper_id', result)
            self.assertIn('code', result)
            self.assertEqual(result.get('evasion_features'), ['amsi_bypass', 'etw_patch'])
        
        asyncio.run(run_test())

def run_tests():
    """Run all unit tests"""
    print("="*60)
    print("BACKEND SERVICE UNIT TESTS")
    print("="*60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestPayloadFactory))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n✅ All unit tests PASSED")
    else:
        print("\n⚠️ Some tests failed")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    try:
        success = run_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
