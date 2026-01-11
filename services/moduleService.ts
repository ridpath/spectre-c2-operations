const BACKEND_URL = 'http://localhost:8000/api/v1';

export interface ModuleExecutionRequest {
  command: string;
  mission_id?: string;
}

export interface ModuleExecutionResult {
  success: boolean;
  output?: string;
  error?: string;
  error_type?: string;
  module?: string;
  timestamp?: string;
  execution_id?: string;
  type?: string;
  [key: string]: any;
}

export interface ModuleInfo {
  id: string;
  name: string;
  category: string;
  description: string;
  opsec_risk: string;
  noise_level: number;
  required_integrity: string;
  author: string;
  commands: Array<{
    trigger: string;
    description: string;
  }>;
}

class ModuleService {
  private getAuthHeaders(): HeadersInit {
    const token = localStorage.getItem('spectre_access_token');
    return {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : '',
    };
  }

  async executeModule(request: ModuleExecutionRequest): Promise<ModuleExecutionResult> {
    try {
      const response = await fetch(`${BACKEND_URL}/modules/execute`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const error = await response.json();
        return {
          success: false,
          error: error.detail || 'Module execution failed',
          error_type: 'http_error'
        };
      }

      const result = await response.json();
      return result;
    } catch (error) {
      return {
        success: false,
        error: `Network error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        error_type: 'network_error'
      };
    }
  }

  async listModules(category?: string): Promise<ModuleInfo[]> {
    try {
      const url = category 
        ? `${BACKEND_URL}/modules/list?category=${encodeURIComponent(category)}`
        : `${BACKEND_URL}/modules/list`;

      const response = await fetch(url, {
        method: 'GET',
        headers: this.getAuthHeaders(),
      });

      if (!response.ok) {
        console.error('Failed to fetch modules');
        return [];
      }

      const data = await response.json();
      return data.modules || [];
    } catch (error) {
      console.error('Error fetching modules:', error);
      return [];
    }
  }

  formatModuleOutput(result: ModuleExecutionResult): string {
    if (!result.success) {
      return `[ERROR] ${result.error || 'Execution failed'}`;
    }

    let output = result.output || '';
    
    // Add execution metadata
    const metadata: string[] = [];
    if (result.module) metadata.push(`Module: ${result.module}`);
    if (result.type) metadata.push(`Type: ${result.type}`);
    if (result.execution_id) metadata.push(`Execution ID: ${result.execution_id}`);
    
    if (metadata.length > 0) {
      output = `[${metadata.join(' | ')}]\n\n${output}`;
    }

    return output;
  }

  getModuleColor(category: string): string {
    const colors: Record<string, string> = {
      'Recon': '#10b981',
      'Exploitation': '#ef4444',
      'Post-Ex': '#f59e0b',
      'Persistence': '#8b5cf6',
    };
    return colors[category] || '#6b7280';
  }

  getOpsecRiskColor(risk: string): string {
    const colors: Record<string, string> = {
      'Low': '#10b981',
      'Medium': '#f59e0b',
      'High': '#ef4444',
    };
    return colors[risk] || '#6b7280';
  }
}

export const moduleService = new ModuleService();
