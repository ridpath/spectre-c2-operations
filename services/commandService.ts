
import { WinRMConnection } from '../types';

export interface CommandResult {
  output: string;
  type: 'output' | 'error' | 'system';
}

export type ShellContext = 'remote' | 'local';

export const executeCommand = async (
  command: string, 
  connection: WinRMConnection | null,
  context: ShellContext = 'remote'
): Promise<CommandResult> => {
  return new Promise((resolve) => {
    setTimeout(() => {
      const cmd = command.toLowerCase().trim();
      
      // --- CELESTIAL BREACH PHASE II COMMANDS ---
      if (cmd.startsWith('ccsds-inject')) {
        resolve({
          output: "[CCSDS-FORGE] TC Frame Assembly Complete.\n[CCSDS-FORGE] Header: 0x18E5 | APID: 0x3E5 | Length: 12\n[CCSDS-FORGE] CRC-16 Verify: PASS (0xFEA2)\n[CCSDS-FORGE] Uplink Dispatched via S-Band Proxy Node Alpha.\n[CCSDS-FORGE] STATUS: ACK RECEIVED FROM ASSET.",
          type: 'system'
        });
        return;
      }

      if (cmd.startsWith('relay-init')) {
        resolve({
          output: "[Relay-Bounce] Establishing multi-hop orbital bridge...\n[Relay-Bounce] Hop 1 (43105): LATENCY 45ms, SNR 32dB\n[Relay-Bounce] Hop 2 (43569): LATENCY 120ms, SNR 68dB\n[Relay-Bounce] Bridge Active. Ground Station Geo-Obfuscated.",
          type: 'system'
        });
        return;
      }

      if (cmd.startsWith('ccsds-tm-spoof')) {
        resolve({
          output: "[CCSDS-FORGE] Telemetry Injection Engaged.\n[CCSDS-FORGE] Masking EPS state to 'Nominal' while battery discharge fuzzer runs.\n[CCSDS-FORGE] Heartbeat override active.",
          type: 'output'
        });
        return;
      }

      if (cmd.startsWith('fuzz-eps')) {
        resolve({
          output: "[Astro-Fuzzer] Targeting EPS Charge Controller...\n[Astro-Fuzzer] Injecting bit-flip sequence 0xF4A2 (secondary header).\n[Astro-Fuzzer] Result: Detected 12% drop in solar array efficiency. Success.",
          type: 'output'
        });
        return;
      }
      // --- END CELESTIAL BREACH ---

      // LOCAL CORE CONTEXT
      if (context === 'local') {
        switch (true) {
          case cmd === 'ls' || cmd === 'ls -la':
            resolve({
              output: "total 64\ndrwxr-xr-x  2 spectre ops 4096 Jan 20 12:00 factory\ndrwxr-xr-x  2 spectre ops 4096 Jan 20 12:00 orbital_logic\n-rw-r--r--  1 spectre ops   34 Jan 20 12:00 session_logs.txt\n-rwxr-xr-x  1 spectre ops 8290 Jan 20 12:00 celestial_broker",
              type: 'output'
            });
            break;

          default:
            resolve({
              output: `spectre@ops-core:~$ ${command}\n[Exec] Dispatched to local tactical shell...`,
              type: 'output'
            });
        }
        return;
      }

      // REMOTE BEACON CONTEXT
      if (!connection) {
        return resolve({ 
          output: "Error: No active beacon signal locked.", 
          type: 'error' 
        });
      }

      switch (true) {
        case cmd === 'whoami':
          resolve({ 
            output: `${connection.host}\\${connection.username}\n\nSecurity Context:\nSeImpersonatePrivilege : ENABLED\nSeDebugPrivilege      : ENABLED`,
            type: 'output'
          });
          break;
        
        default:
          resolve({
            output: `[Spectre-Beacon] Task assigned. Command '${command}' transmitted via orbital relay. Monitoring response stream...`,
            type: 'output'
          });
      }
    }, 400);
  });
};
