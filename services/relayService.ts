import { moduleService } from './moduleService';

export interface RelayHop {
  satellite_id: string;
  norad_id: number;
  name: string;
  status: 'active' | 'pending' | 'failed';
  latency_ms: number;
  snr_db: number;
}

export interface RelayChain {
  id: string;
  hops: RelayHop[];
  total_latency_ms: number;
  status: 'active' | 'inactive' | 'initializing';
  created_at: string;
}

class RelayService {
  async initializeRelay(hopPattern: string, missionId?: string): Promise<{ success: boolean; output?: string; error?: string }> {
    try {
      const result = await moduleService.executeModule(`relay-init --hops ${hopPattern}`, missionId);
      return {
        success: result.success,
        output: result.output,
        error: result.error
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Relay initialization failed'
      };
    }
  }

  async getRelayStatus(missionId?: string): Promise<{ success: boolean; output?: string; error?: string }> {
    try {
      const result = await moduleService.executeModule('relay-status', missionId);
      return {
        success: result.success,
        output: result.output,
        error: result.error
      };
    } catch (error: any) {
      return {
        success: false,
        error: error.message || 'Failed to get relay status'
      };
    }
  }

  parseMockRelayData(satellites: any[]): RelayChain {
    const availableSats = satellites.filter(s => 
      s.designation && 
      (s.designation.includes('IRIDIUM') || 
       s.designation.includes('STARLINK') || 
       s.designation.includes('STERN'))
    );

    const hops: RelayHop[] = availableSats.slice(0, 3).map((sat, idx) => ({
      satellite_id: sat.id,
      norad_id: sat.noradId,
      name: sat.designation,
      status: 'active' as const,
      latency_ms: 45 + idx * 75,
      snr_db: 32 + idx * 36
    }));

    const total_latency = hops.reduce((sum, hop) => sum + hop.latency_ms, 0);

    return {
      id: `relay-${Date.now()}`,
      hops,
      total_latency_ms: total_latency,
      status: hops.length > 0 ? 'active' : 'inactive',
      created_at: new Date().toISOString()
    };
  }
}

export const relayService = new RelayService();
