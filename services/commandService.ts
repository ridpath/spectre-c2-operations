
import { WinRMConnection } from '../types';

export interface CommandResult {
  output: string;
  type: 'output' | 'error' | 'system';
}

export type ShellContext = 'remote' | 'local';

/**
 * ARCHITECTURAL NOTE: 
 * Set USE_TACTICAL_BRIDGE to true when your FastAPI bridge is operational.
 */
const USE_TACTICAL_BRIDGE = true; // ACTIVATED: Commands now route to backend.py
const BRIDGE_URL = 'http://localhost:8000/api/v1';
const AUTH_TOKEN = 'valid_token'; // Matches backend verify_token dummy check

export const executeCommand = async (
  command: string, 
  connection: WinRMConnection | null,
  context: ShellContext = 'remote'
): Promise<CommandResult> => {
  if (USE_TACTICAL_BRIDGE) {
    try {
      // Mapping frontend CamelCase to backend expected structures
      const connectionPayload = connection ? {
        host: connection.host,
        port: connection.port,
        username: connection.username,
        password: connection.password,
        use_ssl: connection.useSsl,
        auth_method: connection.authMethod.toLowerCase()
      } : null;

      const response = await fetch(`${BRIDGE_URL}/execute`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${AUTH_TOKEN}`
        },
        body: JSON.stringify({ 
          command, 
          context,
          connection: connectionPayload
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        return { output: `BRIDGE_API_ERROR: ${errorData.detail || 'Internal Server Error'}`, type: 'error' };
      }

      return await response.json() as CommandResult;
    } catch (err) {
      return { output: "BRIDGE_ERROR: Connection to Tactical Bridge severed. Verify Python backend status.", type: 'error' };
    }
  }

  // Fallback to internal simulation logic for research lab testing
  return new Promise((resolve) => {
    setTimeout(() => {
      const cmd = command.toLowerCase().trim();
      
      if (cmd.startsWith('ccsds-inject')) {
        resolve({
          output: "[CCSDS-FORGE] TC Frame Assembly Complete.\n[CCSDS-FORGE] Header: 0x18E5 | APID: 0x3E5 | Length: 12\n[CCSDS-FORGE] CRC-16 Verify: PASS (0xFEA2)\n[CCSDS-FORGE] Uplink Dispatched via Tactical Bridge Relay.\n[CCSDS-FORGE] STATUS: ACK RECEIVED.",
          type: 'system'
        });
        return;
      }

      if (cmd.startsWith('relay-init')) {
        resolve({
          output: "[Relay-Bounce] Initializing multi-hop orbital quantum bridge...\n[Relay-Bounce] Hop 1 (43105): 45ms, SNR 32dB\n[Relay-Bounce] Hop 2 (43569): 120ms, SNR 68dB\n[Relay-Bounce] Bridge Active. Terrestrial Geolocation Obfuscated.",
          type: 'system'
        });
        return;
      }

      if (context === 'local') {
        resolve({ output: `spectre@ops-core:~$ ${command}\n[Local] Dispatched to internal logic core.`, type: 'output' });
        return;
      }

      if (!connection) {
        return resolve({ output: "Error: No active beacon signal locked. Establish WinRM session.", type: 'error' });
      }

      resolve({
        output: `[Spectre-Beacon] Tasking assigned to ${connection.host}. Command '${command}' transmitted via bridge. Monitoring response...`,
        type: 'output'
      });
    }, 400);
  });
};
