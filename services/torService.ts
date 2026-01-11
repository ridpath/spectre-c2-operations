const API_URL = 'http://localhost:8000/api/v1';

export interface TorCircuit {
  id: string;
  entry_node: string;
  middle_nodes: string[];
  exit_node: string;
  created_at: string;
  latency_ms: number;
  bandwidth_kbps: number;
}

export interface TorStatus {
  enabled: boolean;
  circuit_id: string;
  entry_guard: string;
  middle_relay: string;
  exit_node: string;
  path: string[];
  country_codes: string[];
  latency_ms: number;
  bandwidth_kbps: number;
  protocol: string;
  is_stable: boolean;
  last_rotated: string;
}

class TorService {
  private getAuthToken(): string {
    return localStorage.getItem('spectre_access_token') || '';
  }

  async getStatus(): Promise<TorStatus | null> {
    try {
      const response = await fetch(`${API_URL}/tor/status`, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        if (response.status === 403 || response.status === 401) {
          console.warn('Not authenticated for Tor status');
          return null;
        }
        throw new Error(`Failed to get Tor status: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to get Tor status:', error);
      return null;
    }
  }

  async rotateCircuit(): Promise<boolean> {
    try {
      const response = await fetch(`${API_URL}/tor/rotate`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      return response.ok;
    } catch (error: any) {
      console.error('Failed to rotate Tor circuit:', error);
      return false;
    }
  }

  generateMockCircuit(): TorStatus {
    const mockNodes = [
      '185.220.101.5', '209.141.55.10', '192.42.116.16', '94.23.250.111',
      '51.15.43.232', '176.10.99.200', '198.98.51.189', '51.77.135.89'
    ];
    
    const shuffle = [...mockNodes].sort(() => Math.random() - 0.5);
    
    return {
      enabled: true,
      circuit_id: Math.random().toString(36).substring(7),
      entry_guard: shuffle[0],
      middle_relay: shuffle[1],
      exit_node: shuffle[2],
      path: ['10.10.14.12', shuffle[0], shuffle[1], shuffle[2]],
      country_codes: ['US', 'DE', 'NL', 'FR'],
      latency_ms: 380 + Math.floor(Math.random() * 100),
      bandwidth_kbps: 1200 + Math.floor(Math.random() * 800),
      protocol: 'SOCKS5h',
      is_stable: Math.random() > 0.1,
      last_rotated: new Date(Date.now() - Math.random() * 3600000).toISOString()
    };
  }
}

export const torService = new TorService();
