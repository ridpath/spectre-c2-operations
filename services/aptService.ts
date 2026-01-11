const API_URL = 'http://localhost:8000/api/v1';

export interface APTChain {
  id: string;
  name: string;
  description: string;
  threat_actor_mimicry: string;
  heat_level: number;
  total_steps: number;
  steps: Array<{
    id: string;
    name: string;
    module: string;
    args: string;
    requires_privilege: string;
    success_criteria: string;
    delay_seconds: number;
  }>;
}

export interface APTExecutionRequest {
  chain_id: string;
  variables?: Record<string, string>;
  pause_on_error?: boolean;
  mission_id?: string;
}

export interface APTExecutionResult {
  execution_id: string;
  chain_id: string;
  chain_name: string;
  threat_actor: string;
  started_at: string;
  completed_at?: string;
  total_steps: number;
  completed_steps: number;
  failed_steps: number;
  success: boolean;
  halted_at_step?: number;
  step_results: Array<{
    step_number: number;
    step_id: string;
    step_name: string;
    module: string;
    started_at: string;
    completed_at?: string;
    success: boolean;
    output?: string;
    error?: string;
    chain_halted?: boolean;
  }>;
}

class APTService {
  private getAuthToken(): string {
    return localStorage.getItem('access_token') || '';
  }

  async listChains(): Promise<{ chains: APTChain[]; total: number }> {
    try {
      const response = await fetch(`${API_URL}/apt/chains`, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to list APT chains: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to list APT chains:', error);
      return { chains: [], total: 0 };
    }
  }

  async getChainDetails(chainId: string): Promise<APTChain | null> {
    try {
      const response = await fetch(`${API_URL}/apt/chains/${chainId}`, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to get chain details: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to get chain details:', error);
      return null;
    }
  }

  async executeChain(request: APTExecutionRequest): Promise<APTExecutionResult> {
    try {
      const response = await fetch(`${API_URL}/apt/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        },
        body: JSON.stringify(request)
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `Chain execution failed: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('APT chain execution error:', error);
      throw error;
    }
  }

  async getExecutionHistory(): Promise<APTExecutionResult[]> {
    try {
      const response = await fetch(`${API_URL}/apt/history`, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to get execution history: ${response.status}`);
      }

      const data = await response.json();
      return data.executions || [];
    } catch (error: any) {
      console.error('Failed to get execution history:', error);
      return [];
    }
  }
}

export const aptService = new APTService();
