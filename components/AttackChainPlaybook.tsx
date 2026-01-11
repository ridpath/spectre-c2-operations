import React, { useState } from 'react';
import { BookOpen, Play, Clock, Target, AlertTriangle, CheckCircle, Zap } from 'lucide-react';
import { AttackPlaybook, AttackStep } from '../types';

interface AttackChainPlaybookProps {
  onExecutePlaybook: (playbook: AttackPlaybook) => void;
  onExecuteStep: (step: AttackStep) => void;
}

const AttackChainPlaybook: React.FC<AttackChainPlaybookProps> = ({ onExecutePlaybook, onExecuteStep }) => {
  const [selectedPlaybook, setSelectedPlaybook] = useState<AttackPlaybook | null>(null);
  const [executingStep, setExecutingStep] = useState<string | null>(null);

  const playbooks: AttackPlaybook[] = [
    {
      id: 'playbook-recon-101',
      name: 'Satellite Reconnaissance 101',
      description: 'Basic passive reconnaissance of satellite telemetry and signal characteristics',
      objective: 'Gather intelligence on satellite operations without active transmission',
      difficulty: 'beginner',
      duration: '15-20 minutes',
      steps: [
        {
          id: 'step-1',
          phase: 'recon',
          tool: 'rtl_power',
          command: 'rtl_power -f 437M -g 40 -i 1s -e 600s signal_scan.csv',
          expectedResult: 'Signal strength data captured over 10 minutes',
          status: 'pending'
        },
        {
          id: 'step-2',
          phase: 'recon',
          tool: 'gr-satellites',
          command: 'gr-satellites ISS --samp-rate 2400000 --iq-file recording.iq --hexdump',
          expectedResult: 'Telemetry frames decoded and displayed',
          status: 'pending'
        },
        {
          id: 'step-3',
          phase: 'recon',
          tool: 'rtl_sdr',
          command: 'rtl_sdr -f 437800000 -s 2048000 -g 40 telemetry.iq',
          expectedResult: 'IQ recording saved for offline analysis',
          status: 'pending'
        }
      ],
      requiredTools: ['RTL-SDR', 'gr-satellites', 'rtl_power'],
      requiredHardware: ['RTL-SDR dongle', 'UHF antenna'],
      legalWarnings: ['Passive monitoring only', 'No transmission', 'Record keeping recommended']
    },
    {
      id: 'playbook-tc-inject',
      name: 'Telecommand Injection Attack',
      description: 'Advanced attack chain for unauthorized telecommand injection into satellite C&C channel',
      objective: 'Gain unauthorized control over satellite subsystems',
      difficulty: 'expert',
      duration: '10 minutes (during pass)',
      steps: [
        {
          id: 'step-1',
          phase: 'recon',
          tool: 'hackrf_sweep',
          command: 'hackrf_sweep -f 430:440 -w 5000000 -l 16 -g 20',
          expectedResult: 'Command frequency identified',
          status: 'pending'
        },
        {
          id: 'step-2',
          phase: 'initial_access',
          tool: 'ccsds-analyzer',
          command: 'ccsds-analyzer --capture --freq 437.8M --duration 60s',
          expectedResult: 'CCSDS packet structure reverse engineered',
          status: 'pending'
        },
        {
          id: 'step-3',
          phase: 'execution',
          tool: 'ccsds-inject',
          command: 'ccsds-inject --apid 0x3E5 --vcid 0 --payload DEADBEEF --crc-check',
          expectedResult: 'Telecommand accepted by satellite',
          status: 'pending'
        },
        {
          id: 'step-4',
          phase: 'execution',
          tool: 'monitor',
          command: 'rtl_sdr -f 437800000 -s 2048000 -g 40 response.iq',
          expectedResult: 'Satellite response captured',
          status: 'pending'
        }
      ],
      requiredTools: ['HackRF One', 'gr-satellites', 'ccsds-tools'],
      requiredHardware: ['HackRF One', 'UHF transmit antenna', 'Power amplifier'],
      legalWarnings: [
        'CRITICAL: Requires written authorization',
        'FCC Part 97 compliance mandatory',
        'Unauthorized transmission is a federal crime',
        'Amateur radio license required'
      ]
    },
    {
      id: 'playbook-telemetry-exfil',
      name: 'Telemetry Exfiltration',
      description: 'Capture and decode satellite housekeeping telemetry for intelligence gathering',
      objective: 'Extract operational data from satellite downlinks',
      difficulty: 'intermediate',
      duration: '30 minutes',
      steps: [
        {
          id: 'step-1',
          phase: 'recon',
          tool: 'gpredict',
          command: 'gpredict --satellite NOAA-15 --predict-pass',
          expectedResult: 'Next pass window identified',
          status: 'pending'
        },
        {
          id: 'step-2',
          phase: 'execution',
          tool: 'rtl_sdr',
          command: 'rtl_sdr -f 137620000 -s 2400000 -g 49.6 noaa15_pass.iq',
          expectedResult: 'Complete pass recorded',
          status: 'pending'
        },
        {
          id: 'step-3',
          phase: 'exfiltration',
          tool: 'gr-satellites',
          command: 'gr-satellites NOAA-15 --iq-file noaa15_pass.iq --hexdump > telemetry.txt',
          expectedResult: 'Telemetry decoded and saved',
          status: 'pending'
        },
        {
          id: 'step-4',
          phase: 'exfiltration',
          tool: 'telemetry-parser',
          command: 'python parse_telemetry.py telemetry.txt --output report.json',
          expectedResult: 'Structured telemetry data extracted',
          status: 'pending'
        }
      ],
      requiredTools: ['RTL-SDR', 'gr-satellites', 'gpredict'],
      requiredHardware: ['RTL-SDR dongle', 'VHF antenna (137 MHz)'],
      legalWarnings: ['Passive monitoring only', 'Comply with local regulations']
    }
  ];

  const getDifficultyColor = (difficulty: AttackPlaybook['difficulty']) => {
    switch (difficulty) {
      case 'beginner': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'intermediate': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'advanced': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'expert': return 'text-red-400 bg-red-500/10 border-red-500/30';
    }
  };

  const getPhaseIcon = (phase: AttackStep['phase']) => {
    switch (phase) {
      case 'recon': return <Target size={12} />;
      case 'initial_access': return <Zap size={12} />;
      case 'execution': return <Play size={12} />;
      case 'persistence': return <Clock size={12} />;
      case 'exfiltration': return <CheckCircle size={12} />;
    }
  };

  return (
    <div className="h-full flex flex-col gap-6">
      <header>
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <BookOpen size={20} /> Attack Playbooks
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">
          Pre-Built Satellite Attack Chains
        </p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1 overflow-hidden">
        <div className="lg:col-span-5 flex flex-col gap-4 overflow-y-auto pr-2">
          {playbooks.map(playbook => (
            <button
              key={playbook.id}
              onClick={() => setSelectedPlaybook(playbook)}
              className={`text-left p-6 rounded-2xl border transition-all ${
                selectedPlaybook?.id === playbook.id
                  ? 'bg-emerald-500/10 border-emerald-500/30'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between gap-2 mb-3">
                <h3 className="text-lg font-black text-slate-300">{playbook.name}</h3>
                <div className={`text-[10px] font-black uppercase px-2 py-1 rounded-lg border ${getDifficultyColor(playbook.difficulty)}`}>
                  {playbook.difficulty}
                </div>
              </div>

              <div className="text-sm text-slate-500 mb-4 leading-relaxed">{playbook.description}</div>

              <div className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <Clock size={12} className="text-slate-600" />
                  <span className="text-slate-400">{playbook.duration}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Target size={12} className="text-slate-600" />
                  <span className="text-slate-400">{playbook.steps.length} steps</span>
                </div>
              </div>
            </button>
          ))}
        </div>

        <div className="lg:col-span-7 flex flex-col gap-4 overflow-y-auto">
          {selectedPlaybook ? (
            <>
              <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div>
                  <h3 className="text-xl font-black text-emerald-400 mb-2">{selectedPlaybook.name}</h3>
                  <div className="text-sm text-slate-400 mb-4">{selectedPlaybook.description}</div>
                  <div className="flex items-center gap-2 text-xs text-blue-400">
                    <Target size={12} />
                    <span className="font-bold uppercase">Objective:</span>
                    <span>{selectedPlaybook.objective}</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div>
                    <div className="text-slate-600 uppercase font-bold mb-2">Required Tools</div>
                    <div className="space-y-1">
                      {selectedPlaybook.requiredTools.map((tool, idx) => (
                        <div key={idx} className="text-slate-400">• {tool}</div>
                      ))}
                    </div>
                  </div>
                  <div>
                    <div className="text-slate-600 uppercase font-bold mb-2">Required Hardware</div>
                    <div className="space-y-1">
                      {selectedPlaybook.requiredHardware.map((hw, idx) => (
                        <div key={idx} className="text-slate-400">• {hw}</div>
                      ))}
                    </div>
                  </div>
                </div>

                {selectedPlaybook.legalWarnings.length > 0 && (
                  <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
                    <div className="flex items-center gap-2 text-red-400 mb-2">
                      <AlertTriangle size={16} />
                      <span className="font-black uppercase text-sm">Legal Warnings</span>
                    </div>
                    <div className="space-y-1 text-xs text-red-300/70">
                      {selectedPlaybook.legalWarnings.map((warning, idx) => (
                        <div key={idx}>• {warning}</div>
                      ))}
                    </div>
                  </div>
                )}

                <button
                  onClick={() => onExecutePlaybook(selectedPlaybook)}
                  className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
                >
                  <Play size={16} />
                  Execute Full Playbook
                </button>
              </div>

              <div className="space-y-3">
                <div className="text-sm font-black uppercase text-slate-400">Attack Chain Steps</div>
                {selectedPlaybook.steps.map((step, idx) => (
                  <div
                    key={step.id}
                    className="bg-slate-900/40 border border-slate-800 rounded-2xl p-4 space-y-3"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 font-black text-sm">
                          {idx + 1}
                        </div>
                        <div>
                          <div className="flex items-center gap-2 text-xs">
                            {getPhaseIcon(step.phase)}
                            <span className="text-blue-400 uppercase font-bold">{step.phase.replace('_', ' ')}</span>
                          </div>
                          <div className="text-xs text-slate-600 font-mono mt-0.5">{step.tool}</div>
                        </div>
                      </div>
                      <div className={`text-[10px] font-black uppercase px-2 py-1 rounded-lg ${
                        step.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400' :
                        step.status === 'executing' ? 'bg-yellow-500/20 text-yellow-400' :
                        step.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                        'bg-slate-800 text-slate-600'
                      }`}>
                        {step.status}
                      </div>
                    </div>

                    <div className="bg-black border border-slate-800 rounded-xl p-3">
                      <div className="text-xs font-bold text-slate-600 uppercase mb-1">Command</div>
                      <pre className="text-xs font-mono text-emerald-400 break-all whitespace-pre-wrap">
                        {step.command}
                      </pre>
                    </div>

                    <div className="text-xs text-slate-500">
                      <span className="font-bold text-slate-400 uppercase">Expected:</span> {step.expectedResult}
                    </div>

                    {step.result && (
                      <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-3">
                        <div className="text-xs font-bold text-blue-400 uppercase mb-1">Result</div>
                        <div className="text-xs text-blue-300/70">{step.result}</div>
                      </div>
                    )}

                    <button
                      onClick={() => {
                        setExecutingStep(step.id);
                        onExecuteStep(step);
                        setTimeout(() => setExecutingStep(null), 2000);
                      }}
                      disabled={executingStep === step.id}
                      className={`w-full py-2 rounded-xl text-white font-bold text-xs flex items-center justify-center gap-2 transition-all ${
                        executingStep === step.id
                          ? 'bg-slate-800 cursor-not-allowed'
                          : 'bg-slate-700 hover:bg-slate-600'
                      }`}
                    >
                      <Play size={12} />
                      {executingStep === step.id ? 'Executing...' : 'Execute Step'}
                    </button>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-center text-slate-600">
              <div>
                <BookOpen size={80} className="mx-auto mb-6 opacity-20" />
                <div className="text-xl font-bold uppercase mb-3">Select a Playbook</div>
                <div className="text-sm">Choose an attack chain from the list to view details and execute</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AttackChainPlaybook;
