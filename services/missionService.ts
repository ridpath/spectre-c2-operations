import { SatelliteMission } from '../types';
import { authService } from './authService';

const BACKEND_URL = 'http://localhost:8000/api/v1';

export const missionService = {
  async getMissions(): Promise<SatelliteMission[]> {
    try {
      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/missions`);

      if (!response.ok) {
        throw new Error('Failed to fetch missions');
      }

      const data = await response.json();
      return data.missions.map((m: any) => ({
        ...m,
        createdAt: new Date(m.created_at),
        startedAt: m.started_at ? new Date(m.started_at) : undefined,
        completedAt: m.completed_at ? new Date(m.completed_at) : undefined,
        nextPass: m.next_pass ? {
          ...m.next_pass,
          startTime: new Date(m.next_pass.start_time),
          endTime: new Date(m.next_pass.end_time)
        } : null
      }));
    } catch (error) {
      console.error('Failed to fetch missions:', error);
      return [];
    }
  },

  async getMission(missionId: string): Promise<SatelliteMission | null> {
    try {
      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/missions/${missionId}`);

      if (!response.ok) {
        return null;
      }

      const m = await response.json();
      return {
        ...m,
        createdAt: new Date(m.created_at),
        startedAt: m.started_at ? new Date(m.started_at) : undefined,
        completedAt: m.completed_at ? new Date(m.completed_at) : undefined,
        nextPass: m.next_pass ? {
          ...m.next_pass,
          startTime: new Date(m.next_pass.start_time),
          endTime: new Date(m.next_pass.end_time)
        } : null
      };
    } catch (error) {
      console.error('Failed to fetch mission:', error);
      return null;
    }
  },

  async createMission(mission: {
    name: string;
    targetSatellite: string;
    targetNoradId: number;
    objective: string;
    authorization: any;
  }): Promise<SatelliteMission> {
    const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/missions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: mission.name,
        target_satellite: mission.targetSatellite,
        target_norad_id: mission.targetNoradId,
        objective: mission.objective,
        authorization: mission.authorization
      })
    });

    if (!response.ok) {
      throw new Error('Failed to create mission');
    }

    const m = await response.json();
    return {
      ...m,
      createdAt: new Date(m.created_at),
      targetSatellite: m.target_satellite,
      targetNoradId: m.target_norad_id,
      attackChain: m.attack_chain || [],
      nextPass: null
    };
  },

  async updateMission(missionId: string, updates: {
    status?: string;
    attackChain?: any[];
    evidence?: string[];
  }): Promise<SatelliteMission> {
    const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/missions/${missionId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        status: updates.status,
        attack_chain: updates.attackChain,
        evidence: updates.evidence
      })
    });

    if (!response.ok) {
      throw new Error('Failed to update mission');
    }

    const m = await response.json();
    return {
      ...m,
      createdAt: new Date(m.created_at),
      targetSatellite: m.target_satellite,
      targetNoradId: m.target_norad_id,
      attackChain: m.attack_chain || [],
      nextPass: null
    };
  },

  async deleteMission(missionId: string): Promise<void> {
    const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/missions/${missionId}`, {
      method: 'DELETE'
    });

    if (!response.ok) {
      throw new Error('Failed to delete mission');
    }
  }
};
