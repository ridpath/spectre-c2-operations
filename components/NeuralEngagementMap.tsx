
import React, { useState, useEffect } from 'react';
import { WinRMConnection, C2Task } from '../types';
import { Shield, Zap, Target, Activity, HardDrive, Share2, MousePointer2, AlertTriangle, Cpu, SignalHigh } from 'lucide-react';

interface NeuralMapProps {
  connections: WinRMConnection[];
  tasks: C2Task[];
  onSelectTarget: (id: string) => void;
}

const NeuralEngagementMap: React.FC<NeuralMapProps> = ({ connections, tasks, onSelectTarget }) => {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [globalEntropy, setGlobalEntropy] = useState(12);

  // Dynamic noise simulation
  useEffect(() => {
    const interval = setInterval(() => {
      setGlobalEntropy(prev => {
        const delta = Math.sin(Date.now() / 2000) * 2;
        return Math.max(5, Math.min(95, prev + delta));
      });
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-1000">
      {/* Global Signal HUD */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-[2rem] flex flex-col gap-4 relative overflow-hidden group">
          <div className="flex justify-between items-center">
            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Global Entropy</span>
            <Activity size={14} className={globalEntropy > 70 ? 'text-red-500 animate-pulse' : 'text-emerald-500'} />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-3xl font-black text-white">{Math.floor(globalEntropy)}%</span>
            <span className="text-[10px] text-slate-600 font-bold mb-1 uppercase tracking-tighter">Detection Probability</span>
          </div>
          <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
             <div 
               className={`h-full transition-all duration-1000 ${globalEntropy > 70 ? 'bg-red-500' : 'bg-emerald-500'}`} 
               style={{ width: `${globalEntropy}%` }}
             ></div>
          </div>
          <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 blur-3xl rounded-full"></div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-[2rem] flex flex-col gap-4">
          <div className="flex justify-between items-center">
            <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Active Links</span>
            <SignalHigh size={14} className="text-blue-500" />
          </div>
          <div className="flex items-end gap-2">
            <span className="text-3xl font-black text-white">{connections.length}</span>
            <span className="text-[10px] text-slate-600 font-bold mb-1 uppercase tracking-tighter">Live Beacons</span>
          </div>
          <div className="flex -space-x-2">
             {connections.map(c => (
               <div key={c.id} className="w-6 h-6 rounded-full border-2 border-[#020617] bg-slate-800 flex items-center justify-center text-[8px] font-black">{c.host.charAt(0)}</div>
             ))}
          </div>
        </div>

        <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800 p-6 rounded-[2rem] flex flex-col justify-center">
           <div className="flex items-center gap-6">
              <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-500">
                 <Cpu size={24} />
              </div>
              <div>
                <h4 className="text-[11px] font-black text-slate-200 uppercase tracking-widest">Autonomous Engine</h4>
                <p className="text-[9px] text-slate-500 mt-1 uppercase tracking-tight">3 Agents currently executing "Auto-Discovery" routines.</p>
              </div>
           </div>
        </div>
      </div>

      {/* Neural Graph */}
      <div className="flex-1 bg-[#010309] border border-white/5 rounded-[3rem] relative overflow-hidden shadow-2xl group/map">
        {/* Dynamic Scan Line */}
        <div className="absolute inset-0 pointer-events-none opacity-10">
           <div className="w-full h-[1px] bg-emerald-500 absolute top-0 left-0 animate-scan"></div>
        </div>
        
        {/* Grid and Noise Background */}
        <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 1px 1px, #fff 1px, transparent 0)', backgroundSize: '32px 32px' }}></div>
        
        {/* C2 Center Point */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center z-10">
           <div className="w-32 h-32 rounded-full bg-emerald-500/5 border border-emerald-500/20 flex items-center justify-center relative shadow-[0_0_100px_rgba(16,185,129,0.1)]">
              <Shield className="text-emerald-500" size={48} />
              <div className="absolute inset-0 rounded-full border border-emerald-500/40 animate-ping opacity-10"></div>
           </div>
           <span className="mt-4 text-[9px] font-black text-emerald-500 uppercase tracking-[0.5em]">Spectre Overlord</span>
        </div>

        {/* Neural Nodes */}
        {connections.map((c, i) => {
          const angle = (i * 360) / connections.length;
          const radius = 220 + (Math.sin(Date.now() / 1000 + i) * 10); // Floating effect
          const x = Math.cos((angle * Math.PI) / 180) * radius;
          const y = Math.sin((angle * Math.PI) / 180) * radius;
          
          return (
            <div 
              key={c.id}
              onClick={() => onSelectTarget(c.id)}
              onMouseEnter={() => setHoveredNode(c.id)}
              onMouseLeave={() => setHoveredNode(null)}
              className={`absolute w-20 h-20 -translate-x-1/2 -translate-y-1/2 transition-all cursor-pointer z-20 group/node
                ${hoveredNode === c.id ? 'scale-125' : ''}`}
              style={{ left: `calc(50% + ${x}px)`, top: `calc(50% + ${y}px)` }}
            >
              {/* Connection Tendrils */}
              <svg className="absolute inset-0 w-full h-full pointer-events-none overflow-visible" style={{ left: '-50%', top: '-50%' }}>
                <defs>
                  <linearGradient id={`grad-${c.id}`} x1="0%" y1="0%" x2="100%" y2="0%">
                    <stop offset="0%" stopColor="#10b981" stopOpacity="0" />
                    <stop offset="100%" stopColor="#10b981" stopOpacity="0.4" />
                  </linearGradient>
                </defs>
                <path 
                  d={`M ${radius} ${radius} Q ${radius/2} ${radius/2} ${-x} ${-y}`}
                  fill="none" 
                  stroke={`url(#grad-${c.id})`}
                  strokeWidth="1.5"
                  className={`${c.status === 'connected' ? 'animate-pulse' : 'opacity-10'}`}
                />
              </svg>

              <div className={`w-full h-full rounded-[2rem] bg-slate-900/90 border-2 backdrop-blur-md flex flex-col items-center justify-center relative overflow-hidden transition-all
                ${c.status === 'connected' ? 'border-emerald-500/40 shadow-[0_0_20px_rgba(16,185,129,0.2)]' : 'border-slate-800 grayscale opacity-40'}`}>
                
                <div className={`absolute inset-0 bg-gradient-to-br transition-opacity ${c.entropy > 70 ? 'from-red-500/10 to-transparent' : 'from-emerald-500/10 to-transparent opacity-0 group-hover/node:opacity-100'}`}></div>

                <HardDrive size={24} className={c.status === 'connected' ? 'text-emerald-400' : 'text-slate-600'} />
                <span className="text-[8px] font-black text-slate-400 mt-2 uppercase tracking-tighter">{c.host.split('.').pop()}</span>
                
                {/* Micro Metrics */}
                <div className="absolute top-2 right-2 flex gap-1">
                   {c.integrityLevel === 'SYSTEM' && <Zap size={8} className="text-yellow-500" />}
                   <div className={`w-1.5 h-1.5 rounded-full ${c.status === 'connected' ? 'bg-emerald-500 shadow-[0_0_5px_#10b981]' : 'bg-slate-800'}`}></div>
                </div>
              </div>

              {/* Node Tooltip Overlay */}
              {hoveredNode === c.id && (
                <div className="absolute top-24 left-1/2 -translate-x-1/2 w-48 bg-[#0b1120] border border-white/10 rounded-2xl p-4 shadow-2xl z-50 pointer-events-none animate-in zoom-in duration-200">
                  <div className="flex justify-between items-start mb-3">
                    <span className="text-[10px] font-black text-slate-200 uppercase">{c.host}</span>
                    <span className="text-[8px] font-mono text-slate-500">[{c.integrityLevel}]</span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between text-[8px] font-black uppercase text-slate-600">
                      <span>Signal Entropy</span>
                      <span className={c.entropy > 50 ? 'text-red-400' : 'text-emerald-400'}>{c.entropy}%</span>
                    </div>
                    <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
                       <div className={`h-full ${c.entropy > 50 ? 'bg-red-500' : 'bg-emerald-500'}`} style={{ width: `${c.entropy}%` }}></div>
                    </div>
                  </div>
                  <div className="mt-4 pt-3 border-t border-white/5 flex flex-wrap gap-1">
                     {c.capabilities.slice(0, 3).map(cap => (
                       <span key={cap} className="text-[7px] font-black uppercase bg-white/5 text-slate-400 px-1.5 py-0.5 rounded">{cap.split('-')[1]}</span>
                     ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {connections.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-800 space-y-4">
             <div className="w-20 h-20 rounded-[2rem] bg-white/5 border border-white/5 flex items-center justify-center">
               <MousePointer2 size={32} className="opacity-20 animate-bounce" />
             </div>
             <p className="text-[10px] font-black uppercase tracking-[0.4em] opacity-20">Awaiting Signal Synchronization</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default NeuralEngagementMap;
