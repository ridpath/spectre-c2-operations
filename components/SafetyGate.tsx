import React, { useState, useEffect } from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, X, Check } from 'lucide-react';
import { TransmissionRequest, SafetyCheck as SafetyCheckType } from '../types';

interface SafetyGateProps {
  transmissionRequest: TransmissionRequest;
  onApprove: () => void;
  onDeny: () => void;
}

const SafetyGate: React.FC<SafetyGateProps> = ({ transmissionRequest, onApprove, onDeny }) => {
  const [checks, setChecks] = useState<SafetyCheckType[]>([]);
  const [checkResults, setCheckResults] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const safetyChecks: SafetyCheckType[] = [
      {
        id: 'authorization',
        name: 'Written Authorization',
        check: () => transmissionRequest.authorization.hasPermission,
        severity: 'critical',
        message: 'Written authorization document required for transmission',
        category: 'legal'
      },
      {
        id: 'frequency_legal',
        name: 'Frequency Compliance',
        check: () => {
          const freq = transmissionRequest.frequency;
          return (freq >= 144 && freq <= 148) || 
                 (freq >= 420 && freq <= 450) ||
                 (freq >= 1240 && freq <= 1300);
        },
        severity: 'critical',
        message: 'Transmission frequency must be within amateur radio allocations',
        category: 'legal'
      },
      {
        id: 'power_limit',
        name: 'Power Limit',
        check: () => transmissionRequest.power <= 100,
        severity: 'critical',
        message: 'Transmission power exceeds legal limit (100W max for amateur radio)',
        category: 'legal'
      },
      {
        id: 'pass_window',
        name: 'Satellite Visibility',
        check: () => true,
        severity: 'warning',
        message: 'Satellite may not be visible - verify pass window',
        category: 'operational'
      },
      {
        id: 'equipment_ready',
        name: 'Equipment Check',
        check: () => true,
        severity: 'warning',
        message: 'Verify antenna pointing and SDR connection',
        category: 'technical'
      },
      {
        id: 'interference_check',
        name: 'Interference Analysis',
        check: () => true,
        severity: 'warning',
        message: 'Check for other ground station activity on frequency',
        category: 'operational'
      }
    ];

    setChecks(safetyChecks);

    const results: Record<string, boolean> = {};
    safetyChecks.forEach(check => {
      results[check.id] = check.check();
    });
    setCheckResults(results);
  }, [transmissionRequest]);

  const criticalFailures = checks.filter(c => c.severity === 'critical' && !checkResults[c.id]);
  const warnings = checks.filter(c => c.severity === 'warning' && !checkResults[c.id]);
  const canProceed = criticalFailures.length === 0;

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border-2 border-red-500 rounded-3xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-8 space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <ShieldAlert size={32} className="text-red-500" />
              <div>
                <h2 className="text-xl font-black uppercase text-red-400">
                  Transmission Safety Gate
                </h2>
                <p className="text-xs text-slate-500 uppercase font-bold mt-1">
                  Pre-Transmission Validation Required
                </p>
              </div>
            </div>
            <button
              onClick={onDeny}
              className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <X size={20} className="text-slate-500" />
            </button>
          </div>

          <div className="bg-slate-950 border border-slate-800 rounded-2xl p-4 space-y-2 text-xs">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-slate-600 font-bold uppercase">Target:</span>
                <div className="text-blue-400 font-mono">{transmissionRequest.targetSatellite}</div>
              </div>
              <div>
                <span className="text-slate-600 font-bold uppercase">Frequency:</span>
                <div className="text-blue-400 font-mono">{transmissionRequest.frequency} MHz</div>
              </div>
              <div>
                <span className="text-slate-600 font-bold uppercase">Power:</span>
                <div className="text-blue-400 font-mono">{transmissionRequest.power} W</div>
              </div>
              <div>
                <span className="text-slate-600 font-bold uppercase">Modulation:</span>
                <div className="text-blue-400 font-mono">{transmissionRequest.modulation}</div>
              </div>
            </div>
          </div>

          {criticalFailures.length > 0 && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-2xl p-4 space-y-3">
              <div className="flex items-center gap-2 text-red-400">
                <AlertTriangle size={20} />
                <span className="font-black uppercase text-sm">Critical Safety Failures</span>
              </div>
              {criticalFailures.map(check => (
                <div key={check.id} className="flex gap-3 items-start">
                  <X size={16} className="text-red-500 mt-0.5 shrink-0" />
                  <div className="space-y-1">
                    <div className="text-red-400 font-bold text-sm">{check.name}</div>
                    <div className="text-red-300/70 text-xs">{check.message}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {warnings.length > 0 && (
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-2xl p-4 space-y-3">
              <div className="flex items-center gap-2 text-yellow-400">
                <AlertTriangle size={20} />
                <span className="font-black uppercase text-sm">Warnings</span>
              </div>
              {warnings.map(check => (
                <div key={check.id} className="flex gap-3 items-start">
                  <AlertTriangle size={16} className="text-yellow-500 mt-0.5 shrink-0" />
                  <div className="space-y-1">
                    <div className="text-yellow-400 font-bold text-sm">{check.name}</div>
                    <div className="text-yellow-300/70 text-xs">{check.message}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          <div className="space-y-2">
            <div className="text-xs font-black uppercase text-slate-500">All Safety Checks</div>
            <div className="space-y-2">
              {checks.map(check => (
                <div
                  key={check.id}
                  className={`flex items-center gap-3 p-3 rounded-xl border ${
                    checkResults[check.id]
                      ? 'bg-emerald-500/5 border-emerald-500/30'
                      : check.severity === 'critical'
                      ? 'bg-red-500/5 border-red-500/30'
                      : 'bg-yellow-500/5 border-yellow-500/30'
                  }`}
                >
                  {checkResults[check.id] ? (
                    <Check size={16} className="text-emerald-500 shrink-0" />
                  ) : (
                    <X size={16} className={check.severity === 'critical' ? 'text-red-500' : 'text-yellow-500'} shrink-0 />
                  )}
                  <div className="flex-1">
                    <div className={`text-sm font-bold ${
                      checkResults[check.id] ? 'text-emerald-400' : 
                      check.severity === 'critical' ? 'text-red-400' : 'text-yellow-400'
                    }`}>
                      {check.name}
                    </div>
                    <div className="text-xs text-slate-500 uppercase">
                      {check.category} • {check.severity}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="flex gap-3">
            <button
              onClick={onDeny}
              className="flex-1 py-4 bg-slate-800 hover:bg-slate-700 rounded-2xl text-white font-black uppercase text-sm transition-all"
            >
              Cancel Transmission
            </button>
            <button
              onClick={onApprove}
              disabled={!canProceed}
              className={`flex-1 py-4 rounded-2xl font-black uppercase text-sm transition-all flex items-center justify-center gap-2 ${
                canProceed
                  ? 'bg-red-600 hover:bg-red-500 text-white'
                  : 'bg-slate-800 text-slate-600 cursor-not-allowed'
              }`}
            >
              {canProceed ? (
                <>
                  <ShieldCheck size={18} />
                  Authorize Transmission
                </>
              ) : (
                <>
                  <ShieldAlert size={18} />
                  Cannot Proceed
                </>
              )}
            </button>
          </div>

          {canProceed && (
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 text-xs text-yellow-400 text-center font-bold">
              By authorizing this transmission, you confirm having proper legal authorization and accept full responsibility for compliance with applicable regulations.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SafetyGate;
