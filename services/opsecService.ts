const API_URL = 'http://localhost:8000/api/v1';

export interface OpsecLog {
  id: string;
  action: string;
  user: string;
  timestamp: string;
  details: Record<string, any>;
  risk_level: 'low' | 'medium' | 'high' | 'critical';
}

class OpsecService {
  private getAuthToken(): string {
    return localStorage.getItem('access_token') || '';
  }

  async getLogs(limit: number = 100): Promise<OpsecLog[]> {
    try {
      const response = await fetch(`${API_URL}/opsec/logs?limit=${limit}`, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        if (response.status === 403 || response.status === 401) {
          console.warn('Not authenticated for OpSec logs');
          return [];
        }
        throw new Error(`Failed to get OpSec logs: ${response.status}`);
      }

      const data = await response.json();
      return data.logs || [];
    } catch (error: any) {
      console.error('Failed to get OpSec logs:', error);
      return [];
    }
  }

  generateMockLogs(): OpsecLog[] {
    const actions = [
      'module_execution', 'agent_checkin', 'credential_harvest', 
      'lateral_movement', 'data_exfiltration', 'persistence_established'
    ];
    
    const logs: OpsecLog[] = [];
    for (let i = 0; i < 10; i++) {
      logs.push({
        id: Math.random().toString(36).substring(7),
        action: actions[Math.floor(Math.random() * actions.length)],
        user: 'admin',
        timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
        details: { target: '192.168.1.10', success: true },
        risk_level: ['low', 'medium', 'high'][Math.floor(Math.random() * 3)] as any
      });
    }
    
    return logs.sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }
}

export const opsecService = new OpsecService();
