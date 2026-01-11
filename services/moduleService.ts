const API_URL = 'http://localhost:8000/api/v1';

export interface ModuleExecutionResult {
  success: boolean;
  module?: string;
  timestamp?: string;
  execution_id?: string;
  output?: string;
  error?: string;
  error_type?: string;
  required_privilege?: string;
}

export interface ModuleInfo {
  name: string;
  description: string;
  category: string;
  requires_privilege: string;
  example: string;
  args?: string[];
  risk_level?: string;
}

class ModuleService {
  private getAuthToken(): string {
    return localStorage.getItem('access_token') || '';
  }

  async executeModule(command: string, missionId?: string): Promise<ModuleExecutionResult> {
    try {
      const response = await fetch(`${API_URL}/modules/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        },
        body: JSON.stringify({
          command,
          mission_id: missionId
        })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `Module execution failed: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Module execution error:', error);
      return {
        success: false,
        error: error.message || 'Module execution failed',
        error_type: 'network_error'
      };
    }
  }

  async listModules(category?: string): Promise<{ modules: ModuleInfo[]; total: number; categories: string[] }> {
    try {
      const url = category 
        ? `${API_URL}/modules/list?category=${encodeURIComponent(category)}`
        : `${API_URL}/modules/list`;

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to list modules: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to list modules:', error);
      return { modules: [], total: 0, categories: [] };
    }
  }

  isOrbitalModule(moduleName: string): boolean {
    const orbitalModules = [
      'scan-orbital',
      'gs-mimic',
      'ccsds-inject',
      'ccsds-tm-spoof',
      'relay-init',
      'relay-status',
      'persist-aos'
    ];
    return orbitalModules.includes(moduleName);
  }

  isReconModule(moduleName: string): boolean {
    const reconModules = [
      'enum-domain',
      'scan-network',
      'scan-ports',
      'scan-services',
      'bloodhound',
      'enum-processes',
      'enum-modules'
    ];
    return reconModules.includes(moduleName);
  }

  isExploitModule(moduleName: string): boolean {
    const exploitModules = [
      'exploit-eternalblue',
      'exploit-zerologon',
      'exploit-printnightmare',
      'kerberoast'
    ];
    return exploitModules.includes(moduleName);
  }
}

export const moduleService = new ModuleService();
