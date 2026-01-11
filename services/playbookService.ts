import { AttackPlaybook, AttackStep } from '../types';
import { authService } from './authService';

const BACKEND_URL = 'http://localhost:8000/api/v1';

export const playbookService = {
  async getPlaybooks(): Promise<AttackPlaybook[]> {
    try {
      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/playbooks`);

      if (!response.ok) {
        throw new Error('Failed to fetch playbooks');
      }

      const data = await response.json();
      return data.playbooks;
    } catch (error) {
      console.error('Failed to fetch playbooks:', error);
      return [];
    }
  },

  async getPlaybook(playbookId: string): Promise<AttackPlaybook | null> {
    try {
      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/playbooks/${playbookId}`);

      if (!response.ok) {
        return null;
      }

      return await response.json();
    } catch (error) {
      console.error('Failed to fetch playbook:', error);
      return null;
    }
  },

  async executePlaybook(playbookId: string, missionId?: string): Promise<{ status: string; execution_id: string }> {
    try {
      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/playbooks/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          playbook_id: playbookId,
          mission_id: missionId
        })
      });

      if (!response.ok) {
        throw new Error('Failed to execute playbook');
      }

      return await response.json();
    } catch (error) {
      console.error('Playbook execution error:', error);
      throw error;
    }
  },

  async executeStep(stepId: string, playbookId: string, missionId?: string): Promise<{ status: string; result: string }> {
    try {
      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/playbooks/step/execute`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          step_id: stepId,
          playbook_id: playbookId,
          mission_id: missionId
        })
      });

      if (!response.ok) {
        throw new Error('Failed to execute step');
      }

      return await response.json();
    } catch (error) {
      console.error('Step execution error:', error);
      throw error;
    }
  }
};
