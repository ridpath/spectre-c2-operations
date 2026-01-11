const API_URL = 'http://localhost:8000/api/v1';

export interface Evidence {
  id: string;
  mission_id: string;
  timestamp: string;
  category: 'hash' | 'credential' | 'screenshot' | 'iq' | 'file' | 'module_execution' | 'scan' | 'exploit';
  description: string;
  data?: string;
  file_path?: string;
  file_size?: number;
  metadata?: Record<string, any>;
  tags?: string[];
  satellite_name?: string;
  frequency?: number;
  signal_strength?: number;
}

export interface CreateEvidenceRequest {
  mission_id: string;
  category: string;
  description: string;
  data?: string;
  metadata?: Record<string, any>;
  tags?: string[];
  satellite_name?: string;
  frequency?: number;
  signal_strength?: number;
}

class EvidenceService {
  private getAuthToken(): string {
    return localStorage.getItem('access_token') || '';
  }

  async getEvidence(missionId?: string): Promise<Evidence[]> {
    try {
      const url = missionId 
        ? `${API_URL}/evidence?mission_id=${encodeURIComponent(missionId)}`
        : `${API_URL}/evidence`;

      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch evidence: ${response.status}`);
      }

      const data = await response.json();
      return data.evidence || [];
    } catch (error: any) {
      console.error('Failed to fetch evidence:', error);
      return [];
    }
  }

  async createEvidence(request: CreateEvidenceRequest): Promise<Evidence | null> {
    try {
      const response = await fetch(`${API_URL}/evidence`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.getAuthToken()}`
        },
        body: JSON.stringify(request)
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `Failed to create evidence: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to create evidence:', error);
      return null;
    }
  }

  async deleteEvidence(evidenceId: string): Promise<boolean> {
    try {
      const response = await fetch(`${API_URL}/evidence/${evidenceId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${this.getAuthToken()}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to delete evidence: ${response.status}`);
      }

      return true;
    } catch (error: any) {
      console.error('Failed to delete evidence:', error);
      return false;
    }
  }

  async uploadEvidenceFile(
    missionId: string, 
    file: File, 
    description: string, 
    category: string = 'file'
  ): Promise<Evidence | null> {
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await fetch(
        `${API_URL}/evidence/upload?mission_id=${missionId}&description=${encodeURIComponent(description)}&category=${category}`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.getAuthToken()}`
          },
          body: formData
        }
      );

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `Failed to upload evidence: ${response.status}`);
      }

      return await response.json();
    } catch (error: any) {
      console.error('Failed to upload evidence file:', error);
      return null;
    }
  }

  getCategoryIcon(category: string): string {
    const icons: Record<string, string> = {
      hash: 'Key',
      credential: 'ShieldCheck',
      screenshot: 'Camera',
      iq: 'Waves',
      file: 'HardDrive',
      module_execution: 'Terminal',
      scan: 'Search',
      exploit: 'Bug'
    };
    return icons[category] || 'Database';
  }

  getCategoryColor(category: string): string {
    const colors: Record<string, string> = {
      hash: 'text-purple-400',
      credential: 'text-blue-400',
      screenshot: 'text-yellow-400',
      iq: 'text-emerald-400',
      file: 'text-cyan-400',
      module_execution: 'text-orange-400',
      scan: 'text-pink-400',
      exploit: 'text-red-400'
    };
    return colors[category] || 'text-slate-400';
  }
}

export const evidenceService = new EvidenceService();
