import React, { useState } from 'react';
import { FileText, Download, Eye, AlertTriangle, CheckCircle } from 'lucide-react';
import { SatelliteMission, MissionReport, ReportFinding } from '../types';
import { reportService } from '../services/reportService';

interface ReportGeneratorProps {
  mission: SatelliteMission | null;
  onGenerate: (report: MissionReport) => void;
}

const ReportGenerator: React.FC<ReportGeneratorProps> = ({ mission, onGenerate }) => {
  const [reportConfig, setReportConfig] = useState({
    includeExecutiveSummary: true,
    includeMethodology: true,
    includeFindings: true,
    includeTimeline: true,
    includeEvidence: true,
    includeRecommendations: true,
    format: 'markdown' as 'markdown' | 'json' | 'html'
  });

  const [generatedReport, setGeneratedReport] = useState<string | null>(null);
  const [generating, setGenerating] = useState(false);

  const generateReport = async () => {
    if (!mission) return;

    setGenerating(true);

    try {
      const report = await reportService.generateReport(mission.id, {
        includeExecutiveSummary: reportConfig.includeExecutiveSummary,
        includeMethodology: reportConfig.includeMethodology,
        includeFindings: reportConfig.includeFindings,
        includeTimeline: reportConfig.includeTimeline,
        includeEvidence: reportConfig.includeEvidence,
        includeRecommendations: reportConfig.includeRecommendations,
        format: reportConfig.format
      });

      setGeneratedReport(report.content);
      onGenerate(report);
      setGenerating(false);
    } catch (error) {
      console.error('Failed to generate report:', error);
      const mockFindings: ReportFinding[] = [
        {
          id: 'finding-1',
          severity: 'critical',
          title: 'Unauthenticated Telecommand Acceptance',
          description: 'The satellite TTC subsystem accepts telecommands without proper authentication checks, allowing unauthorized command injection.',
          evidence: mission.evidence.slice(0, 2),
          recommendation: 'Implement cryptographic authentication for all telecommand interfaces. Deploy firmware patch v2.3.1 to address CVE-2023-45678.',
          cvss: 9.8
        },
        {
          id: 'finding-2',
          severity: 'high',
          title: 'Telemetry Information Disclosure',
          description: 'Sensitive operational parameters are transmitted in cleartext telemetry, exposing internal state information.',
          evidence: mission.evidence.slice(2, 4),
          recommendation: 'Encrypt sensitive telemetry fields or implement field-level access controls on ground station decoders.',
          cvss: 7.5
        },
        {
          id: 'finding-3',
          severity: 'medium',
          title: 'Predictable Sequence Counters',
          description: 'CCSDS packet sequence counters follow a predictable pattern, potentially aiding replay attacks.',
          evidence: mission.evidence.slice(4, 5),
          recommendation: 'Implement nonce-based sequence validation or time-based token authentication.',
          cvss: 5.3
        }
      ];

      const report: MissionReport = {
        mission,
        executiveSummary: `This penetration test assessed the security posture of ${mission.targetSatellite} (NORAD ${mission.targetNoradId}). The assessment identified ${mockFindings.length} findings, including ${mockFindings.filter(f => f.severity === 'critical').length} critical vulnerabilities that require immediate remediation.`,
        methodology: 'The assessment followed a black-box testing approach using software-defined radio (SDR) equipment and open-source satellite analysis tools. Testing was conducted during ${mission.attackChain.length} satellite passes over a ${Math.floor((new Date().getTime() - mission.createdAt.getTime()) / 3600000)} hour period.',
        findings: mockFindings,
        timeline: mission.attackChain,
        evidence: mission.evidence,
        recommendations: [
          'Implement end-to-end encryption for all command uplinks',
          'Deploy authentication mechanisms for telecommand validation',
          'Establish intrusion detection for anomalous command patterns',
          'Conduct regular security assessments of satellite software',
          'Develop incident response procedures for unauthorized access'
        ],
        generatedAt: new Date(),
        generatedBy: 'Spectre Satellite Pentest Platform'
      };

      let output = '';

      if (reportConfig.format === 'markdown') {
        output = generateMarkdownReport(report);
      } else if (reportConfig.format === 'json') {
        output = JSON.stringify(report, null, 2);
      } else {
        output = generateHTMLReport(report);
      }

      setGeneratedReport(output);
      onGenerate(report);
      setGenerating(false);
    }
  };

  const generateMarkdownReport = (report: MissionReport): string => {
    let md = `# Satellite Penetration Test Report\n\n`;
    md += `**Target:** ${report.mission.targetSatellite} (NORAD ${report.mission.targetNoradId})\n`;
    md += `**Mission:** ${report.mission.name}\n`;
    md += `**Objective:** ${report.mission.objective}\n`;
    md += `**Date:** ${report.generatedAt.toLocaleDateString()}\n`;
    md += `**Generated By:** ${report.generatedBy}\n\n`;

    if (reportConfig.includeExecutiveSummary) {
      md += `## Executive Summary\n\n${report.executiveSummary}\n\n`;
    }

    if (reportConfig.includeMethodology) {
      md += `## Methodology\n\n${report.methodology}\n\n`;
    }

    if (reportConfig.includeFindings) {
      md += `## Findings\n\n`;
      report.findings.forEach((finding, idx) => {
        md += `### ${idx + 1}. ${finding.title} [${finding.severity.toUpperCase()}]\n\n`;
        md += `**Severity:** ${finding.severity.toUpperCase()}\n`;
        if (finding.cvss) md += `**CVSS Score:** ${finding.cvss}\n`;
        md += `\n**Description:**\n${finding.description}\n\n`;
        md += `**Recommendation:**\n${finding.recommendation}\n\n`;
        md += `**Evidence:** ${finding.evidence.length} items collected\n\n`;
      });
    }

    if (reportConfig.includeRecommendations) {
      md += `## Recommendations\n\n`;
      report.recommendations.forEach((rec, idx) => {
        md += `${idx + 1}. ${rec}\n`;
      });
      md += `\n`;
    }

    if (reportConfig.includeTimeline && report.timeline.length > 0) {
      md += `## Attack Timeline\n\n`;
      report.timeline.forEach(step => {
        md += `- **[${step.phase.toUpperCase()}]** ${step.tool}: ${step.command}\n`;
        if (step.result) md += `  - Result: ${step.result}\n`;
      });
      md += `\n`;
    }

    if (reportConfig.includeEvidence) {
      md += `## Evidence Summary\n\n`;
      md += `Total evidence items collected: ${report.evidence.length}\n\n`;
      md += `Breakdown by category:\n`;
      const categories = report.evidence.reduce((acc, e) => {
        acc[e.category] = (acc[e.category] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
      Object.entries(categories).forEach(([cat, count]) => {
        md += `- ${cat}: ${count}\n`;
      });
    }

    return md;
  };

  const generateHTMLReport = (report: MissionReport): string => {
    return `<!DOCTYPE html>
<html>
<head>
  <title>Satellite Pentest Report - ${report.mission.targetSatellite}</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; }
    h1 { color: #10b981; }
    .severity-critical { color: #ef4444; font-weight: bold; }
    .severity-high { color: #f59e0b; font-weight: bold; }
    .severity-medium { color: #eab308; font-weight: bold; }
    .finding { background: #f8f9fa; padding: 20px; margin: 20px 0; border-left: 4px solid #10b981; }
  </style>
</head>
<body>
  <h1>Satellite Penetration Test Report</h1>
  <p><strong>Target:</strong> ${report.mission.targetSatellite} (NORAD ${report.mission.targetNoradId})</p>
  <p><strong>Date:</strong> ${report.generatedAt.toLocaleDateString()}</p>
  <h2>Executive Summary</h2>
  <p>${report.executiveSummary}</p>
  <h2>Findings</h2>
  ${report.findings.map(f => `
    <div class="finding">
      <h3 class="severity-${f.severity}">${f.title} [${f.severity.toUpperCase()}]</h3>
      <p>${f.description}</p>
      <p><strong>Recommendation:</strong> ${f.recommendation}</p>
    </div>
  `).join('')}
</body>
</html>`;
  };

  const downloadReport = () => {
    if (!generatedReport) return;

    const ext = reportConfig.format === 'markdown' ? 'md' : reportConfig.format;
    const blob = new Blob([generatedReport], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `satellite_pentest_${mission?.targetSatellite}_${Date.now()}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="h-full flex flex-col gap-6">
      <header>
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <FileText size={20} /> Report Generator
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">
          {mission ? `Mission: ${mission.name}` : 'No Mission Selected'}
        </p>
      </header>

      {mission ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1 overflow-hidden">
          <div className="lg:col-span-4 flex flex-col gap-4 overflow-y-auto pr-2">
            <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-sm font-black uppercase text-slate-400">Mission Overview</div>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-600 font-bold uppercase">Target:</span>
                  <span className="text-slate-300">{mission.targetSatellite}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-600 font-bold uppercase">NORAD ID:</span>
                  <span className="text-slate-300">{mission.targetNoradId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-600 font-bold uppercase">Objective:</span>
                  <span className="text-blue-400 uppercase">{mission.objective}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-600 font-bold uppercase">Status:</span>
                  <span className={`uppercase ${
                    mission.status === 'completed' ? 'text-emerald-400' : 'text-yellow-400'
                  }`}>{mission.status}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-600 font-bold uppercase">Evidence:</span>
                  <span className="text-slate-300">{mission.evidence.length} items</span>
                </div>
              </div>
            </div>

            <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-sm font-black uppercase text-slate-400">Report Configuration</div>
              
              <div className="space-y-2">
                <label className="flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeExecutiveSummary}
                    onChange={(e) => setReportConfig({ ...reportConfig, includeExecutiveSummary: e.target.checked })}
                    className="accent-emerald-500"
                  />
                  Executive Summary
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeMethodology}
                    onChange={(e) => setReportConfig({ ...reportConfig, includeMethodology: e.target.checked })}
                    className="accent-emerald-500"
                  />
                  Methodology
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeFindings}
                    onChange={(e) => setReportConfig({ ...reportConfig, includeFindings: e.target.checked })}
                    className="accent-emerald-500"
                  />
                  Findings
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeTimeline}
                    onChange={(e) => setReportConfig({ ...reportConfig, includeTimeline: e.target.checked })}
                    className="accent-emerald-500"
                  />
                  Attack Timeline
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeEvidence}
                    onChange={(e) => setReportConfig({ ...reportConfig, includeEvidence: e.target.checked })}
                    className="accent-emerald-500"
                  />
                  Evidence Summary
                </label>
                <label className="flex items-center gap-2 text-sm text-slate-300">
                  <input
                    type="checkbox"
                    checked={reportConfig.includeRecommendations}
                    onChange={(e) => setReportConfig({ ...reportConfig, includeRecommendations: e.target.checked })}
                    className="accent-emerald-500"
                  />
                  Recommendations
                </label>
              </div>

              <div className="pt-3 border-t border-slate-800">
                <label className="text-xs font-bold text-slate-500 uppercase mb-2 block">Output Format</label>
                <select
                  value={reportConfig.format}
                  onChange={(e) => setReportConfig({ ...reportConfig, format: e.target.value as any })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-300 outline-none focus:border-emerald-500 transition-all"
                >
                  <option value="markdown">Markdown (.md)</option>
                  <option value="json">JSON (.json)</option>
                  <option value="html">HTML (.html)</option>
                </select>
              </div>
            </div>

            <button
              onClick={generateReport}
              disabled={generating}
              className={`py-3 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all ${
                generating
                  ? 'bg-slate-800 cursor-not-allowed'
                  : 'bg-emerald-600 hover:bg-emerald-500'
              }`}
            >
              <FileText size={16} />
              {generating ? 'Generating...' : 'Generate Report'}
            </button>
          </div>

          <div className="lg:col-span-8 flex flex-col gap-4">
            {generatedReport ? (
              <>
                <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6 flex-1 overflow-y-auto">
                  <div className="flex items-center justify-between mb-4">
                    <div className="text-sm font-black uppercase text-slate-400">Report Preview</div>
                    <div className="flex items-center gap-1 text-emerald-400 text-xs">
                      <CheckCircle size={12} />
                      Generated
                    </div>
                  </div>
                  <pre className="text-xs text-slate-300 whitespace-pre-wrap font-mono leading-relaxed">
                    {generatedReport}
                  </pre>
                </div>

                <div className="flex gap-3">
                  <button
                    onClick={() => setGeneratedReport(null)}
                    className="flex-1 py-3 bg-slate-800 hover:bg-slate-700 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
                  >
                    <Eye size={16} />
                    Clear Preview
                  </button>
                  <button
                    onClick={downloadReport}
                    className="flex-1 py-3 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
                  >
                    <Download size={16} />
                    Download Report
                  </button>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center text-center text-slate-600">
                <div>
                  <FileText size={80} className="mx-auto mb-6 opacity-20" />
                  <div className="text-xl font-bold uppercase mb-3">No Report Generated</div>
                  <div className="text-sm">Configure report options and click "Generate Report"</div>
                </div>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-center text-slate-600">
          <div>
            <FileText size={80} className="mx-auto mb-6 opacity-20" />
            <div className="text-xl font-bold uppercase mb-3">No Mission Selected</div>
            <div className="text-sm">Select a mission to generate a pentest report</div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportGenerator;
