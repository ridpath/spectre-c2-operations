#!/usr/bin/env python3
import sys

try:
    from module_executor import module_executor
    print("[+] Module executor imported successfully")
    print(f"[+] Total handlers: {len(module_executor.all_handlers)}")
    print(f"[+] Recon: {len(module_executor.recon_handlers)}")
    print(f"[+] Exploitation: {len(module_executor.exploit_handlers)}")
    print(f"[+] Post-Ex: {len(module_executor.postex_handlers)}")
    print(f"[+] Persistence: {len(module_executor.persist_handlers)}")
    
    # Test a simple module
    print("\n[*] Testing enum-domain module...")
    result = module_executor.execute_module("enum-domain --users", "operator", "User")
    print(f"[+] Module execution: {'SUCCESS' if result['success'] else 'FAILED'}")
    if result['success']:
        print(f"[+] Output preview: {result['output'][:100]}...")
    
    sys.exit(0)
except Exception as e:
    print(f"[!] Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
