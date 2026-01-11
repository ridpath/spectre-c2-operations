#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WebSocket endpoint test"""

import asyncio
import json
import sys
from websockets import connect

async def test_orbital_websocket():
    """Test orbital WebSocket stream"""
    uri = "ws://localhost:8000/ws/orbital/25544"
    print(f"Connecting to {uri}...")
    
    try:
        async with connect(uri) as websocket:
            print("[+] Connected to orbital stream")
            
            for i in range(3):
                message = await websocket.recv()
                data = json.loads(message)
                print(f"[{i+1}] Received: lat={data.get('latitude', 'N/A')}, lon={data.get('longitude', 'N/A')}, alt={data.get('altitude', 'N/A')}")
            
            print("[+] Orbital WebSocket test PASSED")
            return True
    except Exception as e:
        print(f"[-] Orbital WebSocket test FAILED: {e}")
        return False

async def test_spectrum_websocket():
    """Test spectrum WebSocket stream"""
    uri = "ws://localhost:8000/ws/spectrum"
    print(f"\nConnecting to {uri}...")
    
    try:
        async with connect(uri) as websocket:
            print("[+] Connected to spectrum stream")
            
            for i in range(3):
                message = await websocket.recv()
                data = json.loads(message)
                print(f"[{i+1}] Received: {len(data.get('data', []))} spectrum points, modulation={data.get('modulation', 'N/A')}")
            
            print("[+] Spectrum WebSocket test PASSED")
            return True
    except Exception as e:
        print(f"[-] Spectrum WebSocket test FAILED: {e}")
        return False

async def main():
    print("="*60)
    print("WEBSOCKET ENDPOINT TESTS")
    print("="*60)
    
    results = []
    results.append(await test_orbital_websocket())
    results.append(await test_spectrum_websocket())
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    print(f"Orbital WebSocket:  {'PASS' if results[0] else 'FAIL'}")
    print(f"Spectrum WebSocket: {'PASS' if results[1] else 'FAIL'}")
    print(f"\nResults: {sum(results)}/2 passed ({int(sum(results)/2*100)}%)")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
