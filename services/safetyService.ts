import { SafetyCheck } from '../types';
import { authService } from './authService';

const BACKEND_URL = 'http://localhost:8000/api/v1';

interface SafetyCheckResult {
  approved: boolean;
  checks: Array<{
    id: string;
    name: string;
    severity: 'warning' | 'critical';
    passed: boolean;
    message: string;
    category: 'legal' | 'technical' | 'operational';
  }>;
  warnings: any[];
  critical_failures: any[];
}

export const safetyService = {
  async checkTransmission(
    frequency: number,
    power: number,
    modulation: string,
    targetSatellite: string
  ): Promise<SafetyCheckResult> {
    try {
      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/safety/check`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          frequency,
          power,
          modulation,
          target_satellite: targetSatellite
        })
      });

      if (!response.ok) {
        throw new Error('Safety check failed');
      }

      return await response.json();
    } catch (error) {
      console.error('Safety check error:', error);
      return {
        approved: false,
        checks: [{
          id: 'error',
          name: 'Backend Connection',
          severity: 'critical',
          passed: false,
          message: 'Failed to connect to safety check backend',
          category: 'technical'
        }],
        warnings: [],
        critical_failures: []
      };
    }
  },

  async getClientSideChecks(frequency: number, power: number): SafetyCheck[] {
    const checks: SafetyCheck[] = [];

    checks.push({
      id: 'freq-range',
      name: 'Frequency Range',
      check: () => frequency >= 30 && frequency <= 3000,
      severity: 'critical',
      message: frequency >= 30 && frequency <= 3000
        ? 'Frequency within operational range'
        : `Frequency ${frequency} MHz outside safe range (30-3000 MHz)`,
      category: 'technical'
    });

    const amateurBands = [
      [144, 148],
      [420, 450],
      [902, 928],
      [1240, 1300]
    ];
    const isAmateur = amateurBands.some(([low, high]) => frequency >= low && frequency <= high);

    checks.push({
      id: 'amateur-band',
      name: 'Amateur Band',
      check: () => isAmateur,
      severity: 'critical',
      message: isAmateur
        ? 'Frequency in amateur radio band'
        : `${frequency} MHz not in amateur bands - FCC authorization required`,
      category: 'legal'
    });

    checks.push({
      id: 'power-limit',
      name: 'Power Limit',
      check: () => power <= 100,
      severity: 'critical',
      message: power <= 100
        ? 'Power within safe limits'
        : `Power ${power}W exceeds safe limit (100W)`,
      category: 'operational'
    });

    return checks;
  }
};
