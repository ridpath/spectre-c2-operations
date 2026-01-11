const API_URL = 'http://localhost:8000/api/v1';

export type AgentStatus = 'active' | 'inactive' | 'disconnected' | 'compromised';
export type AgentType = 'implant' | 'beacon' | 'relay' | 'orbital';
export type TaskStatus = 'pending' | 'executing' | 'completed' | 'failed';

export interface C2Agent {
  id: string;
  hostname: string;
  ip_address: string;
  agent_type: AgentType;
  status: AgentStatus;
  os: string;
  arch: string;
  username: string;
  process_name: string;
  pid: number;
  parent_pid: number;
  integrity_level: string;
  first_seen: string;
  last_seen: string;
  checkin_interval: number;
  metadata?: Record<string, any>;
}

export interface C2Task {
  id: string;
  agent_id: string;
  command: string;
  status: TaskStatus;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  output?: string;
  error?: string;
}

class AgentService {
  private getAuthToken(): string {
    return localStorage.getItem('access_token') || '';
  }

  async listAgents(agentType?: AgentType, status?: AgentStatus): Promise<C2Agent[]> {
    try {
      let url = `${API_URL}/c2/agents`;
      const params = new URLSearchParams();
      if (agentType) params.append('agent_type', agentType);
      if (status) params.append('status', status);
      if (params.toString()) url += `?${params.toString()}`;

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to list agents: ${response.status}`);
      }

      const data = await response.json();
      return data.agents || [];
    } catch (error: any) {
      console.error('Failed to list agents:', error);
      return [];
    }
  }

  async getAgent(agentId: string): Promise<C2Agent | null> {
    try {
      const response = await fetch(`${API_URL}/c2/agents/${agentId}`, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        return null;
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to get agent:', error);
      return null;
    }
  }

  async registerAgent(agentData: {
    hostname: string;
    ip_address: string;
    agent_type: AgentType;
    os: string;
    arch: string;
    username: string;
    process_name: string;
    pid: number;
    parent_pid: number;
    integrity_level: string;
    checkin_interval?: number;
    metadata?: Record<string, any>;
  }): Promise<C2Agent | null> {
    try {
      const response = await fetch(`${API_URL}/c2/agents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        },
        body: JSON.stringify(agentData)
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `Failed to register agent: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to register agent:', error);
      return null;
    }
  }

  async taskAgent(agentId: string, command: string): Promise<C2Task | null> {
    try {
      const response = await fetch(`${API_URL}/c2/agents/${agentId}/tasks`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        },
        body: JSON.stringify({ command })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `Failed to task agent: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to task agent:', error);
      return null;
    }
  }

  async getAgentTasks(agentId: string): Promise<C2Task[]> {
    try {
      const response = await fetch(`${API_URL}/c2/agents/${agentId}/tasks`, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to get agent tasks: ${response.status}`);
      }

      const data = await response.json();
      return data.tasks || [];
    } catch (error: any) {
      console.error('Failed to get agent tasks:', error);
      return [];
    }
  }

  async deleteAgent(agentId: string): Promise<boolean> {
    try {
      const response = await fetch(`${API_URL}/c2/agents/${agentId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to delete agent: ${response.status}`);
      }

      return true;
    } catch (error: any) {
      console.error('Failed to delete agent:', error);
      return false;
    }
  }

  getStatusColor(status: AgentStatus): string {
    const colors: Record<AgentStatus, string> = {
      active: 'text-emerald-400',
      inactive: 'text-yellow-400',
      disconnected: 'text-slate-500',
      compromised: 'text-red-400'
    };
    return colors[status] || 'text-slate-400';
  }

  getTypeIcon(type: AgentType): string {
    const icons: Record<AgentType, string> = {
      implant: 'Bug',
      beacon: 'Radio',
      relay: 'Network',
      orbital: 'Satellite'
    };
    return icons[type] || 'HardDrive';
  }
}

export const agentService = new AgentService();
