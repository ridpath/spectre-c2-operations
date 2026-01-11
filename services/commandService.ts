
import { WinRMConnection } from '../types';
import { moduleService } from './moduleService';

export interface CommandResult {
  output: string;
  type: 'output' | 'error' | 'system';
}

export type ShellContext = 'remote' | 'local';

const USE_TACTICAL_BRIDGE = true;
const BRIDGE_URL = 'http://localhost:8000/api/v1';

function getAuthToken(): string {
  return localStorage.getItem('access_token') || '';
}

const isModuleCommand = (cmd: string): boolean => {
  const modulePatterns = [
    'enum-domain', 'scan-network', 'scan-ports', 'scan-services', 'bloodhound',
    'enum-processes', 'enum-modules', 'scan-orbital', 'exploit-eternalblue',
    'exploit-zerologon', 'exploit-printnightmare', 'ccsds-inject', 'ccsds-tm-spoof',
    'kerberoast', 'harvest-creds', 'lateral-psexec', 'lateral-wmi', 'steal-token',
    'revert-token', 'exfil-smb', 'relay-init', 'relay-status', 'persist-schtask',
    'persist-registry', 'persist-service', 'persist-wmi', 'golden-ticket',
    'persist-aos', 'gs-mimic'
  ];
  
  const cmdLower = cmd.toLowerCase().trim();
  return modulePatterns.some(pattern => cmdLower.startsWith(pattern));
};

export const executeCommand = async (
  command: string, 
  connection: WinRMConnection | null,
  context: ShellContext = 'remote'
): Promise<CommandResult> => {
  if (USE_TACTICAL_BRIDGE) {
    try {
      if (context === 'local' && isModuleCommand(command)) {
        const result = await moduleService.executeModule(command);
        
        if (result.success) {
          return {
            output: result.output || `[MODULE] ${result.module} executed successfully\n${JSON.stringify(result, null, 2)}`,
            type: 'system'
          };
        } else {
          return {
            output: `[MODULE_ERROR] ${result.error}\nError Type: ${result.error_type}${result.required_privilege ? `\nRequired Privilege: ${result.required_privilege}` : ''}`,
            type: 'error'
          };
        }
      }

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
          'Authorization': `Bearer ${getAuthToken()}`
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
    } catch (err: any) {
      return { output: `BRIDGE_ERROR: ${err.message || 'Connection to Tactical Bridge severed'}`, type: 'error' };
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
