import { MissionReport } from '../types';
import { authService } from './authService';

const BACKEND_URL = 'http://localhost:8000/api/v1';

export const reportService = {
  async generateReport(
    missionId: string,
    config: {
      includeExecutiveSummary?: boolean;
      includeMethodology?: boolean;
      includeFindings?: boolean;
      includeTimeline?: boolean;
      includeEvidence?: boolean;
      includeRecommendations?: boolean;
      format?: 'markdown' | 'json' | 'html';
    } = {}
  ): Promise<MissionReport & { content: string }> {
    const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/reports/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        mission_id: missionId,
        include_executive_summary: config.includeExecutiveSummary ?? true,
        include_methodology: config.includeMethodology ?? true,
        include_findings: config.includeFindings ?? true,
        include_timeline: config.includeTimeline ?? true,
        include_evidence: config.includeEvidence ?? true,
        include_recommendations: config.includeRecommendations ?? true,
        format: config.format ?? 'markdown'
      })
    });

    if (!response.ok) {
      throw new Error('Failed to generate report');
    }

    const report = await response.json();
    return {
      mission: {
        ...report.mission,
        createdAt: new Date(report.mission.created_at),
        targetSatellite: report.mission.target_satellite,
        targetNoradId: report.mission.target_norad_id,
        attackChain: report.mission.attack_chain || [],
        nextPass: null
      },
      executiveSummary: report.executive_summary,
      methodology: report.methodology,
      findings: report.findings,
      timeline: report.timeline,
      evidence: report.evidence.map((e: any) => ({
        ...e,
        timestamp: new Date(e.timestamp),
        missionId: e.mission_id,
        satelliteName: e.satellite_name
      })),
      recommendations: report.recommendations,
      generatedAt: new Date(report.generated_at),
      generatedBy: report.generated_by,
      content: report.content
    };
  },

  async getReports(): Promise<MissionReport[]> {
    try {
      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/reports`);

      if (!response.ok) {
        throw new Error('Failed to fetch reports');
      }

      const data = await response.json();
      return data.reports.map((r: any) => ({
        mission: {
          ...r.mission,
          createdAt: new Date(r.mission.created_at),
          targetSatellite: r.mission.target_satellite,
          targetNoradId: r.mission.target_norad_id,
          attackChain: r.mission.attack_chain || [],
          nextPass: null
        },
        executiveSummary: r.executive_summary,
        methodology: r.methodology,
        findings: r.findings,
        timeline: r.timeline,
        evidence: r.evidence.map((e: any) => ({
          ...e,
          timestamp: new Date(e.timestamp),
          missionId: e.mission_id,
          satelliteName: e.satellite_name
        })),
        recommendations: r.recommendations,
        generatedAt: new Date(r.generated_at),
        generatedBy: r.generated_by
      }));
    } catch (error) {
      console.error('Failed to fetch reports:', error);
      return [];
    }
  }
};
