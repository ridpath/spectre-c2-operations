const API_URL = 'http://localhost:8000/api/v1';

export interface NmapScanRequest {
  target: string;
  scan_type: 'quick' | 'full' | 'vuln' | 'smb' | 'rdp' | 'service' | 'discovery';
  ports?: string;
  cve?: string;
  service?: string;
  mission_id?: string;
}

export interface NmapScanResult {
  success?: boolean;
  error?: string;
  scan_type: string;
  target: string;
  timestamp: string;
  hosts?: Array<{
    ip: string;
    hostname: string;
    state: string;
    ports: Array<{
      port: number;
      protocol: string;
      state: string;
      service: string;
      product: string;
      version: string;
      extrainfo: string;
      cpe: string;
    }>;
  }>;
  findings?: Array<{
    id: string;
    host: string;
    port: number;
    service: string;
    severity: string;
    description: string;
    cve?: string;
  }>;
  total_hosts?: number;
  total_findings?: number;
  nse_results?: Array<{
    host: string;
    port: number;
    script: string;
    output: string;
  }>;
  hosts_found?: number;
}

class NmapService {
  private getAuthToken(): string {
    return localStorage.getItem('access_token') || '';
  }

  async scanTarget(request: NmapScanRequest): Promise<NmapScanResult> {
    try {
      const response = await fetch(`${API_URL}/vulnerabilities/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        },
        body: JSON.stringify(request)
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `Scan failed with status ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Nmap scan error:', error);
      throw error;
    }
  }

  async quickScan(target: string, ports: string = '1-1000', missionId?: string): Promise<NmapScanResult> {
    return this.scanTarget({
      target,
      scan_type: 'quick',
      ports,
      mission_id: missionId
    });
  }

  async fullScan(target: string, missionId?: string): Promise<NmapScanResult> {
    return this.scanTarget({
      target,
      scan_type: 'full',
      mission_id: missionId
    });
  }

  async vulnScan(target: string, cve?: string, missionId?: string): Promise<NmapScanResult> {
    return this.scanTarget({
      target,
      scan_type: 'vuln',
      cve,
      mission_id: missionId
    });
  }

  async smbScan(target: string, missionId?: string): Promise<NmapScanResult> {
    return this.scanTarget({
      target,
      scan_type: 'smb',
      mission_id: missionId
    });
  }

  async rdpScan(target: string, missionId?: string): Promise<NmapScanResult> {
    return this.scanTarget({
      target,
      scan_type: 'rdp',
      mission_id: missionId
    });
  }

  async serviceScan(target: string, service: string, missionId?: string): Promise<NmapScanResult> {
    return this.scanTarget({
      target,
      scan_type: 'service',
      service,
      mission_id: missionId
    });
  }

  async networkDiscovery(subnet: string, missionId?: string): Promise<NmapScanResult> {
    return this.scanTarget({
      target: subnet,
      scan_type: 'discovery',
      mission_id: missionId
    });
  }
}

export const nmapService = new NmapService();
