
import React, { useState, useEffect } from 'react';
import { Globe, Shield, RefreshCw, Lock, Zap, Activity } from 'lucide-react';

const TorEgressMonitor: React.FC = () => {
  const [circuit, setCircuit] = useState<string[]>(['10.10.14.12', '185.220.101.5', '94.23.250.111', 'Hidden Service']);
  const [isRotating, setIsRotating] = useState(false);

  const rotateCircuit = () => {
    setIsRotating(true);
    setTimeout(() => {
      setCircuit(['10.10.14.12', '209.141.55.10', '192.42.116.16', 'Hidden Service']);
      setIsRotating(false);
    }, 2000);
  };

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-500">
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-purple-400 uppercase tracking-tighter flex items-center gap-2">
            <Globe size={20} /> Spectral Anonymity Egress
          </h2>
          <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest mt-1">Onion-Routed Transmission Control</p>
        </div>
        <button 
          onClick={rotateCircuit}
          disabled={isRotating}
          className="px-6 py-2 bg-purple-600/20 border border-purple-500/40 text-purple-400 rounded-full text-[10px] font-black uppercase flex items-center gap-2 hover:bg-purple-600/30 transition-all"
        >
          <RefreshCw size={14} className={isRotating ? 'animate-spin' : ''} />
          Rotate Circuit
        </button>
      </header>

      <div className="flex-1 bg-black/40 border border-white/5 rounded-[3rem] p-12 flex flex-col items-center justify-center relative overflow-hidden">
        {/* Connection Visualizer */}
        <div className="flex items-center gap-8 z-10">
          {circuit.map((hop, i) => (
            <React.Fragment key={i}>
              <div className="flex flex-col items-center gap-4">
                <div className={`w-16 h-16 rounded-2xl flex items-center justify-center border-2 transition-all shadow-2xl
                  ${i === 0 ? 'bg-blue-500/10 border-blue-500/40 text-blue-400' : 
                    i === circuit.length - 1 ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-400' : 
                    'bg-purple-500/10 border-purple-500/40 text-purple-400'}`}>
                  {i === 0 ? <Activity size={24} /> : i === circuit.length - 1 ? <Shield size={24} /> : <Lock size={24} />}
                </div>
                <div className="text-center">
                   <div className="text-[8px] font-black text-slate-500 uppercase tracking-widest">
                      {i === 0 ? 'SOURCE' : i === circuit.length - 1 ? 'EXIT NODE' : `HOP ${i}`}
                   </div>
                   <div className="text-[10px] font-mono text-slate-300 mt-1">{hop}</div>
                </div>
              </div>
              {i < circuit.length - 1 && (
                <div className="w-16 h-px bg-gradient-to-r from-purple-500/50 to-purple-500/10 relative">
                   <div className="absolute top-1/2 left-0 -translate-y-1/2 w-2 h-2 rounded-full bg-purple-500 animate-ping"></div>
                </div>
              )}
            </React.Fragment>
          ))}
        </div>

        {/* Tactical Info Overlay */}
        <div className="mt-20 grid grid-cols-3 gap-10 w-full max-w-4xl">
           <div className="p-6 bg-slate-900/40 rounded-3xl border border-white/5 space-y-2">
              <span className="text-[9px] font-black text-slate-500 uppercase">Latency Jitter</span>
              <div className="text-xl font-black text-purple-400">420ms <span className="text-[10px] text-slate-600">± 12%</span></div>
           </div>
           <div className="p-6 bg-slate-900/40 rounded-3xl border border-white/5 space-y-2">
              <span className="text-[9px] font-black text-slate-500 uppercase">Protocol Wrap</span>
              <div className="text-xl font-black text-blue-400">SOCKS5h</div>
           </div>
           <div className="p-6 bg-slate-900/40 rounded-3xl border border-white/5 space-y-2">
              <span className="text-[9px] font-black text-slate-500 uppercase">Signal Stability</span>
              <div className="text-xl font-black text-emerald-400">OPTIMAL</div>
           </div>
        </div>

        <div className="absolute top-0 left-0 w-full h-full opacity-[0.02] pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 1px 1px, #fff 1px, transparent 0)', backgroundSize: '24px 24px' }}></div>
      </div>
      
      <div className="p-6 bg-purple-500/5 border border-purple-500/10 rounded-3xl flex items-center gap-4">
         <Zap size={20} className="text-purple-400" />
         <p className="text-[10px] text-purple-300/60 font-black uppercase tracking-tight">
           Tactical Note: Tor-routed stagers require a SOCKS5-aware beacon. Ensure the stager is synthesized with 'Onion-Wrap' enabled in the Foundry.
         </p>
      </div>
    </div>
  );
};

export default TorEgressMonitor;
