
import React, { useState } from 'react';
import { WinRMConnection, C2Task } from '../types';
import { Shield, Target, Activity, HardDrive, Share2, MousePointer2, AlertCircle, Signal } from 'lucide-react';

interface NetworkTopologyProps {
  connections: WinRMConnection[];
  tasks: C2Task[];
  onSelectTarget: (id: string) => void;
}

const NetworkTopology: React.FC<NetworkTopologyProps> = ({ connections, tasks, onSelectTarget }) => {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const metrics = [
    { label: 'Active Beacons', value: connections.filter(c => c.status === 'connected').length, icon: <Activity size={14} />, color: 'emerald' },
    { label: 'Total Taskings', value: tasks.length, icon: <Target size={14} />, color: 'blue' },
    { label: 'Detections Blocked', value: 0, icon: <Shield size={14} />, color: 'red' },
    { label: 'Tunnel Uptime', value: '14:22', icon: <Signal size={14} />, color: 'purple' },
  ];

  return (
    <div className="h-full flex flex-col gap-8 animate-in fade-in duration-700">
      {/* Strategic Metrics HUD */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
        {metrics.map(m => (
          <div key={m.label} className="bg-slate-900/40 border border-slate-800 p-6 rounded-[1.5rem] flex items-center justify-between group hover:border-slate-700 transition-all">
            <div className="flex flex-col gap-1">
              <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">{m.label}</span>
              <span className={`text-2xl font-black text-slate-100 group-hover:text-${m.color}-400 transition-colors`}>{m.value}</span>
            </div>
            <div className={`p-4 rounded-2xl bg-${m.color}-500/5 text-${m.color}-500 border border-${m.color}-500/20`}>
              {m.icon}
            </div>
          </div>
        ))}
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-4 gap-8 overflow-hidden">
        <div className="lg:col-span-3 flex flex-col gap-8 overflow-hidden">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 flex-1 flex flex-col relative group overflow-hidden shadow-inner">
            <header className="flex justify-between items-center mb-8 z-20">
              <div>
                <h3 className="text-sm font-black text-emerald-400 uppercase tracking-[0.3em] flex items-center gap-3">
                  <Share2 size={16} /> Asset Topology Map
                </h3>
                <p className="text-[10px] text-slate-500 uppercase mt-2 tracking-widest font-bold">Interactive Engagement Visualization</p>
              </div>
              <div className="flex gap-4">
                 <div className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-[9px] font-black uppercase text-emerald-400">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_10px_#10b981]"></div>
                  Locked
                </div>
                 <div className="flex items-center gap-2 px-4 py-2 bg-blue-500/10 border border-blue-500/20 rounded-xl text-[9px] font-black uppercase text-blue-400">
                  <div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_10px_#3b82f6]"></div>
                  Pivot
                </div>
              </div>
            </header>
            
            <div className="flex-1 relative border border-white/5 rounded-[2rem] bg-[#010309] overflow-hidden shadow-2xl">
              <div className="absolute inset-0 opacity-[0.02] pointer-events-none" style={{ backgroundImage: 'linear-gradient(90deg, #fff 1px, transparent 0), linear-gradient(#fff 1px, transparent 0)', backgroundSize: '40px 40px' }}></div>
              
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
                <div className="w-32 h-32 bg-emerald-500/5 border border-emerald-500/20 rounded-full flex items-center justify-center animate-pulse shadow-[0_0_100px_rgba(16,185,129,0.05)]">
                  <Shield className="text-emerald-500/30" size={56} />
                </div>
                <span className="text-[10px] font-black text-emerald-500/40 mt-4 uppercase tracking-[0.5em]">SPECTRE_CORE</span>
              </div>

              {connections.map((c, i) => {
                const angle = (i * 360) / connections.length;
                const radius = 240;
                const x = Math.cos((angle * Math.PI) / 180) * radius;
                const y = Math.sin((angle * Math.PI) / 180) * radius;
                
                return (
                  <div 
                    key={c.id}
                    onClick={() => { setSelectedNode(c.id); onSelectTarget(c.id); }}
                    className={`absolute w-20 h-20 -translate-x-1/2 -translate-y-1/2 bg-[#0a0f1d] border transition-all cursor-pointer group/node z-10 hover:z-20
                      ${selectedNode === c.id ? 'border-emerald-500 shadow-[0_0_30px_rgba(16,185,129,0.3)] scale-110' : 'border-slate-800 hover:border-slate-500'}`}
                    style={{ 
                      left: `calc(50% + ${x}px)`, 
                      top: `calc(50% + ${y}px)`,
                      borderRadius: '35% 15% 35% 15%' 
                    }}
                  >
                    <svg className="absolute inset-0 w-full h-full pointer-events-none overflow-visible" style={{ left: '-50%', top: '-50%' }}>
                      <line 
                        x1="50%" y1="50%" 
                        x2={`calc(50% - ${x}px)`} y2={`calc(50% - ${y}px)`} 
                        stroke={c.status === 'connected' ? '#10b981' : '#334155'} 
                        strokeWidth="2" 
                        strokeDasharray="6 4"
                        className={`opacity-10 group-hover/node:opacity-40 transition-opacity ${c.status === 'connected' ? 'animate-dash' : ''}`}
                      />
                    </svg>

                    <div className="w-full h-full flex flex-col items-center justify-center relative">
                      <HardDrive size={28} className={c.status === 'connected' ? 'text-emerald-400' : 'text-slate-700'} />
                      <span className="text-[9px] font-black text-slate-400 mt-2 truncate w-16 text-center uppercase tracking-tighter">{c.host.split('.').pop()}</span>
                      
                      {/* Integrity Marker */}
                      <div className="absolute top-2 right-2 flex items-center gap-1">
                        <div className={`w-2 h-2 rounded-full ${c.status === 'connected' ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' : 'bg-slate-800'}`}></div>
                      </div>
                    </div>
                  </div>
                );
              })}

              {connections.length === 0 && (
                <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-800 space-y-6">
                  <div className="w-16 h-16 bg-white/5 rounded-[2rem] flex items-center justify-center animate-bounce">
                    <MousePointer2 size={32} className="opacity-20" />
                  </div>
                  <p className="text-xs font-black uppercase tracking-[0.5em] opacity-20">Awaiting Signal Infiltration</p>
                </div>
              )}
            </div>
          </section>
        </div>

        <div className="space-y-8 overflow-hidden flex flex-col">
          <section className="bg-[#0b1120] border border-white/5 rounded-[2rem] p-8 h-full shadow-2xl relative overflow-hidden flex flex-col">
            <h3 className="text-xs font-black uppercase tracking-widest mb-8 flex items-center gap-3 text-slate-300">
              <Target size={18} className="text-red-500" /> Operational Objectives
            </h3>
            
            <div className="flex-1 overflow-y-auto space-y-6 pr-2 custom-scrollbar">
              {connections.map(c => (
                <div key={c.id} className={`p-6 rounded-2xl border transition-all ${selectedNode === c.id ? 'bg-emerald-500/5 border-emerald-500/30' : 'bg-black/20 border-slate-800 hover:border-slate-700'}`}>
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <div className="text-xs font-black text-slate-200">{c.host}</div>
                      <div className="text-[9px] text-slate-500 uppercase font-black tracking-widest mt-1">{c.agentType}</div>
                    </div>
                    <AlertCircle size={14} className={c.status === 'connected' ? 'text-emerald-500' : 'text-slate-700'} />
                  </div>
                  
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-[8px] font-black uppercase text-slate-600">
                       <span>OpSec State</span>
                       <span className="text-emerald-500">Normal</span>
                    </div>
                    <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
                       <div className="h-full bg-emerald-500 w-full animate-pulse"></div>
                    </div>
                  </div>
                </div>
              ))}
              
              {connections.length === 0 && (
                <div className="h-full flex flex-col items-center justify-center text-center px-4 py-20 opacity-20">
                  <Shield size={48} className="mb-4 text-slate-600" />
                  <p className="text-[10px] font-black uppercase tracking-widest leading-loose">Establish initial access to populate target intelligence.</p>
                </div>
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default NetworkTopology;
