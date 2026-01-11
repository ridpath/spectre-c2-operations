import { EvidenceItem } from '../types';
import { authService } from './authService';

const BACKEND_URL = 'http://localhost:8000/api/v1';
const USE_BACKEND = true;

class EvidenceCollectorService {
  private evidence: EvidenceItem[] = [];
  private listeners: Array<(evidence: EvidenceItem[]) => void> = [];

  async addEvidence(item: Omit<EvidenceItem, 'id' | 'timestamp'>): Promise<EvidenceItem> {
    if (USE_BACKEND) {
      try {
        const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/evidence`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            mission_id: item.missionId,
            category: item.category,
            description: item.description,
            data: item.data,
            metadata: item.metadata,
            tags: item.tags,
            satellite_name: item.satelliteName,
            frequency: item.frequency,
            signal_strength: item.signalStrength
          })
        });

        if (response.ok) {
          const backendItem = await response.json();
          const newItem: EvidenceItem = {
            id: backendItem.id,
            missionId: backendItem.mission_id,
            timestamp: new Date(backendItem.timestamp),
            category: backendItem.category,
            description: backendItem.description,
            data: backendItem.data,
            metadata: backendItem.metadata,
            tags: backendItem.tags,
            satelliteName: backendItem.satellite_name,
            frequency: backendItem.frequency,
            signalStrength: backendItem.signal_strength
          };
          this.evidence.push(newItem);
          this.notifyListeners();
          return newItem;
        }
      } catch (error) {
        console.error('Failed to save evidence to backend:', error);
      }
    }

    const newItem: EvidenceItem = {
      ...item,
      id: `ev-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date()
    };

    this.evidence.push(newItem);
    this.notifyListeners();
    
    this.saveToLocalStorage();
    
    return newItem;
  }

  async captureCommand(
    missionId: string,
    command: string,
    output: string,
    metadata?: Record<string, any>
  ): Promise<EvidenceItem> {
    return await this.addEvidence({
      missionId,
      category: 'command_output',
      description: `Command executed: ${command}`,
      data: JSON.stringify({ command, output }),
      metadata: metadata || {},
      tags: ['command', 'terminal']
    });
  }

  async captureSignal(
    missionId: string,
    satelliteName: string,
    frequency: number,
    signalStrength: number,
    data: string,
    metadata?: Record<string, any>
  ): Promise<EvidenceItem> {
    return await this.addEvidence({
      missionId,
      category: 'signal_recording',
      description: `Signal captured from ${satelliteName} at ${frequency} MHz`,
      data,
      satelliteName,
      frequency,
      signalStrength,
      metadata: metadata || {},
      tags: ['signal', 'rf', satelliteName]
    });
  }

  async capturePacket(
    missionId: string,
    satelliteName: string,
    packetData: string,
    metadata?: Record<string, any>
  ): Promise<EvidenceItem> {
    return await this.addEvidence({
      missionId,
      category: 'packet_capture',
      description: `CCSDS packet captured from ${satelliteName}`,
      data: packetData,
      satelliteName,
      metadata: metadata || {},
      tags: ['packet', 'ccsds', satelliteName]
    });
  }

  async captureTelemetry(
    missionId: string,
    satelliteName: string,
    telemetryData: string,
    metadata?: Record<string, any>
  ): Promise<EvidenceItem> {
    return await this.addEvidence({
      missionId,
      category: 'telemetry_dump',
      description: `Telemetry data from ${satelliteName}`,
      data: telemetryData,
      satelliteName,
      metadata: metadata || {},
      tags: ['telemetry', satelliteName]
    });
  }

  async captureScreenshot(
    missionId: string,
    description: string,
    dataUrl: string,
    tags: string[] = []
  ): Promise<EvidenceItem> {
    return await this.addEvidence({
      missionId,
      category: 'screenshot',
      description,
      data: dataUrl,
      metadata: {},
      tags: ['screenshot', ...tags]
    });
  }

  async getEvidence(missionId?: string): Promise<EvidenceItem[]> {
    if (USE_BACKEND) {
      try {
        const url = missionId
          ? `${BACKEND_URL}/evidence?mission_id=${missionId}`
          : `${BACKEND_URL}/evidence`;

        const response = await fetch(url, {
          headers: {
            'Authorization': `Bearer ${AUTH_TOKEN}`
          }
        });

        if (response.ok) {
          const data = await response.json();
          return data.evidence.map((e: any) => ({
            id: e.id,
            missionId: e.mission_id,
            timestamp: new Date(e.timestamp),
            category: e.category,
            description: e.description,
            data: e.data,
            metadata: e.metadata,
            tags: e.tags,
            satelliteName: e.satellite_name,
            frequency: e.frequency,
            signalStrength: e.signal_strength
          }));
        }
      } catch (error) {
        console.error('Failed to fetch evidence from backend:', error);
      }
    }

    if (missionId) {
      return this.evidence.filter(e => e.missionId === missionId);
    }
    return [...this.evidence];
  }

  async clearEvidence(missionId?: string): Promise<void> {
    if (missionId) {
      this.evidence = this.evidence.filter(e => e.missionId !== missionId);
    } else {
      this.evidence = [];
    }
    this.notifyListeners();
    this.saveToLocalStorage();
  }

  async exportEvidence(missionId?: string): Promise<string> {
    const items = await this.getEvidence(missionId);
    return JSON.stringify(items, null, 2);
  }

  subscribe(listener: (evidence: EvidenceItem[]) => void): () => void {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter(l => l !== listener);
    };
  }

  private notifyListeners(): void {
    this.listeners.forEach(listener => listener([...this.evidence]));
  }

  private saveToLocalStorage(): void {
    try {
      localStorage.setItem('spectre_evidence', JSON.stringify(this.evidence));
    } catch (error) {
      console.error('Failed to save evidence to localStorage:', error);
    }
  }

  loadFromLocalStorage(): void {
    try {
      const stored = localStorage.getItem('spectre_evidence');
      if (stored) {
        this.evidence = JSON.parse(stored);
        this.notifyListeners();
      }
    } catch (error) {
      console.error('Failed to load evidence from localStorage:', error);
    }
  }

  async getStatistics(missionId?: string): Promise<{
    total: number;
    byCategory: Record<string, number>;
    bySatellite: Record<string, number>;
  }> {
    const items = await this.getEvidence(missionId);
    
    const byCategory: Record<string, number> = {};
    const bySatellite: Record<string, number> = {};

    items.forEach(item => {
      byCategory[item.category] = (byCategory[item.category] || 0) + 1;
      if (item.satelliteName) {
        bySatellite[item.satelliteName] = (bySatellite[item.satelliteName] || 0) + 1;
      }
    });

    return {
      total: items.length,
      byCategory,
      bySatellite
    };
  }
}

export const evidenceCollector = new EvidenceCollectorService();
