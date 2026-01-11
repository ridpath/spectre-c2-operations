import React, { useState, useEffect, useRef } from 'react';
import { Radio, TrendingUp, TrendingDown, AlertCircle, Settings, Target, Activity } from 'lucide-react';
import { SignalMeasurement, OrbitalAsset, AntennaState } from '../types';

interface SignalStrengthMonitorProps {
  satellite: OrbitalAsset | null;
  antenna: AntennaState;
  onAdjustAntenna: (az: number, el: number) => void;
  onAutoTrack: () => void;
}

const SignalStrengthMonitor: React.FC<SignalStrengthMonitorProps> = ({
  satellite,
  antenna,
  onAdjustAntenna,
  onAutoTrack
}) => {
  const [measurements, setMeasurements] = useState<SignalMeasurement[]>([]);
  const [currentSignal, setCurrentSignal] = useState<SignalMeasurement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [autoTracking, setAutoTracking] = useState(false);

  useEffect(() => {
    if (!satellite) return;

    const interval = setInterval(() => {
      const newMeasurement: SignalMeasurement = {
        timestamp: new Date(),
        frequency: 437800000,
        signalStrength: -80 + Math.random() * 40,
        snr: 10 + Math.random() * 20,
        noiseFloor: -120 + Math.random() * 10,
        dopplerShift: (Math.random() - 0.5) * 5000,
        satelliteElevation: antenna.elevation,
        satelliteAzimuth: antenna.azimuth
      };

      setCurrentSignal(newMeasurement);
      setMeasurements(prev => [...prev.slice(-60), newMeasurement]);
    }, 1000);

    return () => clearInterval(interval);
  }, [satellite, antenna]);

  useEffect(() => {
    if (!canvasRef.current || measurements.length === 0) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;

    ctx.fillStyle = '#020617';
    ctx.fillRect(0, 0, width, height);

    const maxSignal = -40;
    const minSignal = -120;
    const range = maxSignal - minSignal;

    ctx.strokeStyle = '#10b981';
    ctx.lineWidth = 2;
    ctx.beginPath();

    measurements.forEach((m, idx) => {
      const x = (idx / measurements.length) * width;
      const normalized = (m.signalStrength - minSignal) / range;
      const y = height - (normalized * height);

      if (idx === 0) {
        ctx.moveTo(x, y);
      } else {
        ctx.lineTo(x, y);
      }
    });

    ctx.stroke();

    ctx.strokeStyle = '#475569';
    ctx.setLineDash([5, 5]);
    ctx.beginPath();
    const thresholdY = height - ((-80 - minSignal) / range * height);
    ctx.moveTo(0, thresholdY);
    ctx.lineTo(width, thresholdY);
    ctx.stroke();
    ctx.setLineDash([]);

  }, [measurements]);

  if (!satellite) {
    return (
      <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6">
        <div className="text-center text-slate-600">
          <Radio size={40} className="mx-auto mb-3 opacity-30" />
          <div className="font-bold uppercase text-sm">No Satellite Selected</div>
        </div>
      </div>
    );
  }

  const signalQuality = currentSignal 
    ? currentSignal.signalStrength > -60 ? 'excellent' 
      : currentSignal.signalStrength > -75 ? 'good'
      : currentSignal.signalStrength > -90 ? 'fair'
      : 'poor'
    : 'unknown';

  const signalColor = 
    signalQuality === 'excellent' ? 'text-emerald-400' :
    signalQuality === 'good' ? 'text-blue-400' :
    signalQuality === 'fair' ? 'text-yellow-400' :
    'text-red-400';

  return (
    <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Radio size={20} className="text-emerald-500" />
          <h3 className="text-sm font-black uppercase text-slate-400">Signal Strength Monitor</h3>
        </div>
        <div className={`flex items-center gap-2 ${signalColor}`}>
          {signalQuality === 'poor' || signalQuality === 'fair' ? <TrendingDown size={16} /> : <TrendingUp size={16} />}
          <span className="text-xs font-bold uppercase">{signalQuality}</span>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-1">
          <div className="text-[10px] text-slate-600 uppercase font-bold">Signal Strength</div>
          <div className={`text-2xl font-black ${signalColor}`}>
            {currentSignal?.signalStrength.toFixed(1) || '--'} dBm
          </div>
        </div>
        <div className="space-y-1">
          <div className="text-[10px] text-slate-600 uppercase font-bold">SNR</div>
          <div className="text-2xl font-black text-blue-400">
            {currentSignal?.snr.toFixed(1) || '--'} dB
          </div>
        </div>
        <div className="space-y-1">
          <div className="text-[10px] text-slate-600 uppercase font-bold">Doppler</div>
          <div className="text-2xl font-black text-purple-400">
            {currentSignal ? (currentSignal.dopplerShift / 1000).toFixed(2) : '--'} kHz
          </div>
        </div>
      </div>

      <div className="bg-slate-950 border border-slate-800 rounded-xl p-3">
        <canvas
          ref={canvasRef}
          width={600}
          height={120}
          className="w-full h-full"
        />
      </div>

      {currentSignal && currentSignal.signalStrength < -80 && (
        <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 flex items-start gap-2">
          <AlertCircle size={16} className="text-yellow-500 shrink-0 mt-0.5" />
          <div className="text-xs text-yellow-400">
            <div className="font-bold mb-1">Weak Signal Detected</div>
            <div className="text-yellow-300/70">
              • Increase antenna gain or adjust pointing<br />
              • Verify satellite is above horizon<br />
              • Check for obstructions or interference
            </div>
          </div>
        </div>
      )}

      <div className="space-y-3">
        <div className="text-xs font-black uppercase text-slate-600">Antenna Control</div>
        
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-slate-500 uppercase font-bold">Azimuth</span>
              <span className="text-emerald-400 font-mono">{antenna.azimuth.toFixed(1)}°</span>
            </div>
            <input
              type="range"
              min="0"
              max="360"
              value={antenna.azimuth}
              onChange={(e) => onAdjustAntenna(parseFloat(e.target.value), antenna.elevation)}
              className="w-full accent-emerald-500"
              disabled={autoTracking}
            />
          </div>

          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-slate-500 uppercase font-bold">Elevation</span>
              <span className="text-blue-400 font-mono">{antenna.elevation.toFixed(1)}°</span>
            </div>
            <input
              type="range"
              min="0"
              max="90"
              value={antenna.elevation}
              onChange={(e) => onAdjustAntenna(antenna.azimuth, parseFloat(e.target.value))}
              className="w-full accent-blue-500"
              disabled={autoTracking}
            />
          </div>
        </div>

        <div className="flex gap-3">
          <button
            onClick={() => {
              setAutoTracking(!autoTracking);
              if (!autoTracking) {
                onAutoTrack();
              }
            }}
            className={`flex-1 py-2.5 rounded-xl font-bold text-xs uppercase flex items-center justify-center gap-2 transition-all ${
              autoTracking
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            <Target size={14} />
            {autoTracking ? 'Auto-Tracking Active' : 'Enable Auto-Track'}
          </button>

          <button
            className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 rounded-xl text-slate-400 hover:text-white transition-all"
            title="Antenna Settings"
          >
            <Settings size={14} />
          </button>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <Activity size={12} className={antenna.rotctld_status === 'connected' ? 'text-emerald-500' : 'text-red-500'} />
          <span className={antenna.rotctld_status === 'connected' ? 'text-emerald-400' : 'text-red-400'}>
            rotctld: {antenna.rotctld_status}
          </span>
          {antenna.servo_lock && (
            <span className="ml-auto text-emerald-400">Servo Lock</span>
          )}
        </div>
      </div>
    </div>
  );
};

export default SignalStrengthMonitor;
