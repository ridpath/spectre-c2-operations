import React, { useState, useEffect } from 'react';
import { Radio, TrendingUp, TrendingDown, Target, Zap } from 'lucide-react';
import { OrbitalAsset } from '../types';

interface DopplerCorrectionProps {
  satellite: OrbitalAsset | null;
  baseFrequency: number;
  onCorrectedFrequency: (freq: number) => void;
}

const DopplerCorrection: React.FC<DopplerCorrectionProps> = ({ satellite, baseFrequency, onCorrectedFrequency }) => {
  const [elevation, setElevation] = useState(0);
  const [dopplerShift, setDopplerShift] = useState(0);
  const [correctedFreq, setCorrectedFreq] = useState(baseFrequency);
  const [autoCorrect, setAutoCorrect] = useState(false);

  useEffect(() => {
    if (!satellite) return;

    const interval = setInterval(() => {
      const currentEl = satellite.coords?.alt || 0;
      setElevation(currentEl % 90);
      calculateDoppler(currentEl % 90);
    }, 1000);

    return () => clearInterval(interval);
  }, [satellite, baseFrequency]);

  const calculateDoppler = (el: number) => {
    const SPEED_OF_LIGHT = 299792458;
    const SATELLITE_VELOCITY = 7600;
    
    const elevationRad = (el * Math.PI) / 180;
    const radialVelocity = SATELLITE_VELOCITY * Math.cos(elevationRad);
    
    const shift = (radialVelocity / SPEED_OF_LIGHT) * baseFrequency * 1e6;
    
    const shiftHz = shift;
    setDopplerShift(shiftHz);
    
    const corrected = baseFrequency * 1e6 + shiftHz;
    setCorrectedFreq(corrected / 1e6);
    
    if (autoCorrect) {
      onCorrectedFrequency(corrected / 1e6);
    }
  };

  const getDopplerPhase = () => {
    if (elevation < 45) return 'approach';
    if (elevation > 45) return 'recede';
    return 'tca';
  };

  const phase = getDopplerPhase();

  return (
    <div className="h-full flex flex-col gap-6">
      <header>
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <Radio size={20} /> Doppler Correction
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">
          Real-Time Frequency Adjustment
        </p>
      </header>

      {satellite ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1">
          <div className="space-y-6">
            <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-sm font-black uppercase text-slate-400">Orbital Parameters</div>
              
              <div className="space-y-3">
                <div className="flex justify-between items-center">
                  <span className="text-xs text-slate-600 uppercase font-bold">Satellite:</span>
                  <span className="text-sm text-slate-300">{satellite.designation}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs text-slate-600 uppercase font-bold">Base Frequency:</span>
                  <span className="text-sm font-mono text-blue-400">{baseFrequency.toFixed(6)} MHz</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs text-slate-600 uppercase font-bold">Elevation:</span>
                  <span className="text-sm font-mono text-slate-300">{elevation.toFixed(1)}°</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-xs text-slate-600 uppercase font-bold">Orbital Velocity:</span>
                  <span className="text-sm font-mono text-slate-300">7.6 km/s</span>
                </div>
              </div>
            </div>

            <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-sm font-black uppercase text-slate-400">Doppler Shift</div>
              
              <div className="flex items-center justify-center">
                <div className="text-center">
                  <div className={`text-4xl font-black mb-2 ${
                    dopplerShift > 0 ? 'text-emerald-400' : dopplerShift < 0 ? 'text-red-400' : 'text-slate-400'
                  }`}>
                    {dopplerShift > 0 ? '+' : ''}{(dopplerShift / 1000).toFixed(3)} kHz
                  </div>
                  <div className="flex items-center justify-center gap-2 text-sm">
                    {phase === 'approach' && (
                      <>
                        <TrendingUp size={16} className="text-emerald-500" />
                        <span className="text-emerald-400 font-bold uppercase">Approaching</span>
                      </>
                    )}
                    {phase === 'recede' && (
                      <>
                        <TrendingDown size={16} className="text-red-500" />
                        <span className="text-red-400 font-bold uppercase">Receding</span>
                      </>
                    )}
                    {phase === 'tca' && (
                      <>
                        <Target size={16} className="text-blue-500" />
                        <span className="text-blue-400 font-bold uppercase">TCA (Closest Approach)</span>
                      </>
                    )}
                  </div>
                </div>
              </div>

              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3">
                <div className="h-24 flex items-end justify-between gap-1">
                  {Array.from({ length: 40 }).map((_, i) => {
                    const simEl = (i / 40) * 90;
                    const simShift = Math.cos((simEl * Math.PI) / 180) * 3;
                    const height = Math.abs(simShift) * 8;
                    const isCurrent = Math.abs(simEl - elevation) < 2.5;
                    return (
                      <div
                        key={i}
                        className={`flex-1 rounded-t ${
                          isCurrent ? 'bg-emerald-500' : simShift > 0 ? 'bg-emerald-500/30' : 'bg-red-500/30'
                        }`}
                        style={{ height: `${height}px` }}
                      />
                    );
                  })}
                </div>
                <div className="flex justify-between text-[10px] text-slate-600 mt-2 uppercase font-bold">
                  <span>AOS (0°)</span>
                  <span>TCA (90°)</span>
                  <span>LOS (0°)</span>
                </div>
              </div>
            </div>

            <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between">
                <div className="text-sm font-black uppercase text-slate-400">Auto-Correction</div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={autoCorrect}
                    onChange={(e) => {
                      setAutoCorrect(e.target.checked);
                      if (e.target.checked) {
                        onCorrectedFrequency(correctedFreq);
                      }
                    }}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-600"></div>
                </label>
              </div>
              
              <div className="text-xs text-slate-500">
                {autoCorrect
                  ? 'Frequency automatically adjusted for Doppler shift'
                  : 'Manual frequency adjustment required'}
              </div>

              {autoCorrect && (
                <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-3 flex items-center gap-2">
                  <Zap size={14} className="text-emerald-500" />
                  <span className="text-xs text-emerald-400 font-bold">
                    Auto-tuning to {correctedFreq.toFixed(6)} MHz
                  </span>
                </div>
              )}
            </div>
          </div>

          <div className="space-y-6">
            <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4">
              <div className="text-sm font-black uppercase text-slate-400">Corrected Frequency</div>
              
              <div className="text-center py-6">
                <div className="text-5xl font-black text-emerald-400 mb-2">
                  {correctedFreq.toFixed(6)}
                </div>
                <div className="text-sm text-slate-600 uppercase font-bold">MHz</div>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex justify-between bg-slate-900/40 p-3 rounded-xl">
                  <span className="text-slate-600 font-bold uppercase">Base:</span>
                  <span className="font-mono text-slate-400">{baseFrequency.toFixed(6)} MHz</span>
                </div>
                <div className="flex justify-between bg-slate-900/40 p-3 rounded-xl">
                  <span className="text-slate-600 font-bold uppercase">Shift:</span>
                  <span className={`font-mono ${dopplerShift > 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                    {dopplerShift > 0 ? '+' : ''}{(dopplerShift / 1e6).toFixed(6)} MHz
                  </span>
                </div>
                <div className="flex justify-between bg-emerald-500/10 border border-emerald-500/30 p-3 rounded-xl">
                  <span className="text-emerald-400 font-bold uppercase">Corrected:</span>
                  <span className="font-mono text-emerald-400">{correctedFreq.toFixed(6)} MHz</span>
                </div>
              </div>

              <button
                onClick={() => {
                  onCorrectedFrequency(correctedFreq);
                  navigator.clipboard.writeText(correctedFreq.toFixed(6));
                }}
                className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
              >
                <Target size={16} />
                Apply & Copy Frequency
              </button>
            </div>

            <div className="bg-blue-500/10 border border-blue-500/30 rounded-2xl p-6 space-y-3">
              <div className="text-sm font-black uppercase text-blue-400">Correction Formula</div>
              <div className="text-xs text-blue-300/70 font-mono leading-relaxed">
                f_corrected = f_base + (v_radial / c) × f_base
                <br /><br />
                Where:
                <br />• v_radial = v_sat × cos(elevation)
                <br />• v_sat = 7.6 km/s
                <br />• c = 299,792 km/s
              </div>
            </div>

            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-2xl p-4">
              <div className="text-xs text-yellow-400">
                <div className="font-bold mb-1 uppercase">Usage Tips</div>
                <div className="text-yellow-300/70 space-y-1">
                  • Enable auto-correction for real-time tracking
                  <br />• Maximum shift occurs at AOS/LOS (horizon)
                  <br />• Zero shift at TCA (closest approach)
                  <br />• Typical shift: ±3-5 kHz for UHF band
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-center text-slate-600">
          <div>
            <Radio size={80} className="mx-auto mb-6 opacity-20" />
            <div className="text-xl font-bold uppercase mb-3">No Satellite Selected</div>
            <div className="text-sm">Select a satellite to calculate Doppler correction</div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DopplerCorrection;
