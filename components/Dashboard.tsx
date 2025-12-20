
import React, { useState } from 'react';
import { WinRMConnection, C2Task } from '../types';
import { Shield, Zap, Target, Activity, HardDrive, Share2, MousePointer2 } from 'lucide-react';

interface DashboardProps {
  connections: WinRMConnection[];
  tasks: C2Task[];
  onSelectTarget: (id: string) => void;
}

const Dashboard: React.FC<DashboardProps> = ({ connections, tasks, onSelectTarget }) => {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  return (
    <div className="h-full grid grid-cols-1 lg:grid-cols-4 gap-6 overflow-hidden">
      <div className="lg:col-span-3 space-y-6 flex flex-col overflow-hidden">
        {/* GhostGraph Visualizer */}
        <section className="bg-slate-900/40 border border-slate-800 rounded-3xl p-6 flex-1 flex flex-col relative group">
          <header className="flex justify-between items-center mb-6 z-20">
            <div>
              <h3 className="text-xs font-black text-emerald-400 uppercase tracking-[0.2em] flex items-center gap-2">
                <Share2 size={14} /> GhostGraph Node Topology
              </h3>
              <p className="text-[9px] text-slate-500 uppercase mt-1">Interactive SMB/Native Pivot Map</p>
            </div>
            <div className="flex gap-2">
              <div className="flex items-center gap-2 px-3 py-1 bg-black/40 border border-slate-800 rounded-lg text-[8px] font-black uppercase text-slate-400">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_#10b981]"></div>
                Beacon Active
              </div>
              <div className="flex items-center gap-2 px-3 py-1 bg-black/40 border border-slate-800 rounded-lg text-[8px] font-black uppercase text-slate-400">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-500 shadow-[0_0_8px_#3b82f6]"></div>
                SMB Pivot
              </div>
            </div>
          </header>
          
          <div className="flex-1 relative border border-white/5 rounded-2xl bg-[#020617] overflow-hidden">
            {/* Grid Pattern */}
            <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'linear-gradient(90deg, #fff 1px, transparent 0), linear-gradient(#fff 1px, transparent 0)', backgroundSize: '30px 30px' }}></div>
            
            {/* C2 Hub */}
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center">
              <div className="w-24 h-24 bg-emerald-500/10 border border-emerald-500/40 rounded-full flex items-center justify-center animate-pulse shadow-[0_0_40px_rgba(16,185,129,0.1)]">
                <Shield className="text-emerald-500" size={40} />
              </div>
              <span className="text-[10px] font-black text-emerald-500 mt-2 uppercase tracking-tighter">C2_CONTROL_NODE</span>
            </div>

            {/* Nodes & Connectors */}
            {connections.map((c, i) => {
              const angle = (i * 360) / connections.length;
              const radius = 220;
              const x = Math.cos((angle * Math.PI) / 180) * radius;
              const y = Math.sin((angle * Math.PI) / 180) * radius;
              
              return (
                /* Fixed duplicate style attribute by merging both into one object */
                <div 
                  key={c.id}
                  onClick={() => { setSelectedNode(c.id); onSelectTarget(c.id); }}
                  className={`absolute w-16 h-16 -translate-x-1/2 -translate-y-1/2 bg-[#0f172a] border transition-all cursor-pointer group/node z-10 
                    ${selectedNode === c.id ? 'border-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.2)] scale-110' : 'border-slate-800 hover:border-slate-600'}`}
                  style={{ 
                    left: `calc(50% + ${x}px)`, 
                    top: `calc(50% + ${y}px)`,
                    borderRadius: '25% 10% 25% 10%' 
                  }}
                >
                  {/* Pivot Lines */}
                  <svg className="absolute inset-0 w-full h-full pointer-events-none overflow-visible" style={{ left: '-50%', top: '-50%' }}>
                    <line 
                      x1="50%" y1="50%" 
                      x2={`calc(50% - ${x}px)`} y2={`calc(50% - ${y}px)`} 
                      stroke={c.status === 'connected' ? '#10b981' : '#334155'} 
                      strokeWidth="1" 
                      strokeDasharray="4 2"
                      className="opacity-20 group-hover/node:opacity-100 transition-opacity"
                    />
                  </svg>

                  <div className="w-full h-full flex flex-col items-center justify-center relative overflow-hidden">
                    <HardDrive size={24} className={c.status === 'connected' ? 'text-emerald-400' : 'text-slate-700'} />
                    <span className="text-[8px] font-mono text-slate-400 mt-1 truncate w-12 text-center uppercase tracking-tighter">{c.host.split('.').pop()}</span>
                    
                    {/* Activity Indicator */}
                    <div className="absolute top-1 right-1">
                      <div className={`w-1.5 h-1.5 rounded-full ${c.status === 'connected' ? 'bg-emerald-500 shadow-[0_0_5px_#10b981]' : 'bg-slate-800'}`}></div>
                    </div>
                  </div>
                </div>
              );
            })}

            {connections.length === 0 && (
              <div className="absolute inset-0 flex flex-col items-center justify-center text-slate-600 space-y-4">
                <MousePointer2 size={48} className="opacity-10 animate-bounce" />
                <p className="text-xs font-black uppercase tracking-widest opacity-30">Awaiting Deployment...</p>
              </div>
            )}
          </div>
        </section>

        {/* Tactical Feed (Mythic style) */}
        <section className="h-48 bg-[#0b1120] border border-white/5 rounded-3xl overflow-hidden flex flex-col">
          <div className="px-6 py-3 border-b border-white/5 bg-black/20 flex justify-between items-center">
            <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
              <Activity size={14} className="text-blue-500" /> Live Task Flow
            </h3>
            <span className="text-[8px] font-mono text-emerald-500/50">C2_CHANNEL_ENCRYPTED</span>
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {tasks.map(task => (
              <div key={task.id} className="flex items-center justify-between p-3 bg-slate-900/50 border border-slate-800 rounded-xl">
                <div className="flex items-center gap-4">
                  <div className={`w-1 h-4 rounded-full ${task.status === 'completed' ? 'bg-emerald-500' : 'bg-blue-500'}`}></div>
                  <div className="font-mono text-[10px]">
                    <span className="text-slate-600">[{task.id}]</span>
                    <span className="text-slate-300 ml-3">{task.command}</span>
                  </div>
                </div>
                <div className="px-2 py-0.5 rounded bg-black/40 text-[8px] font-black uppercase text-slate-500">
                  {task.status}
                </div>
              </div>
            ))}
            {tasks.length === 0 && (
              <div className="h-full flex items-center justify-center text-[9px] text-slate-700 uppercase font-black tracking-widest italic">
                No active taskings in the pipe
              </div>
            )}
          </div>
        </section>
      </div>

      {/* Target Inspector & Beacon State */}
      <div className="space-y-6">
        <div className="bg-[#0b1120] border border-white/5 rounded-3xl p-6 h-full shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-500 to-blue-500"></div>
          <h3 className="text-xs font-black uppercase tracking-widest mb-6 flex items-center gap-2 text-slate-300">
            <Target size={16} className="text-red-500" /> Mission Status
          </h3>
          
          <div className="space-y-4">
            {connections.map(c => (
              <div key={c.id} className={`p-4 rounded-2xl border transition-all ${selectedNode === c.id ? 'bg-emerald-500/5 border-emerald-500/20' : 'bg-slate-900/40 border-slate-800'}`}>
                <div className="flex justify-between items-start">
                  <div>
                    <div className="text-[11px] font-black text-slate-200">{c.host}</div>
                    <div className="text-[9px] text-slate-500 uppercase font-bold mt-0.5">{c.agentType}</div>
                  </div>
                  <Zap size={14} className={c.status === 'connected' ? 'text-yellow-500 animate-pulse' : 'text-slate-700'} />
                </div>
                
                <div className="mt-4 grid grid-cols-2 gap-2">
                  <div className="bg-black/40 p-2 rounded-xl border border-white/5 text-center">
                    <div className="text-[7px] font-black text-slate-600 uppercase">Latency</div>
                    <div className="text-[10px] font-mono text-emerald-400">14ms</div>
                  </div>
                  <div className="bg-black/40 p-2 rounded-xl border border-white/5 text-center">
                    <div className="text-[7px] font-black text-slate-600 uppercase">Sessions</div>
                    <div className="text-[10px] font-mono text-blue-400">1</div>
                  </div>
                </div>
              </div>
            ))}
            {connections.length === 0 && (
              <div className="py-20 text-center opacity-20">
                <Target size={48} className="mx-auto mb-4" />
                <p className="text-[10px] font-black uppercase tracking-widest">Target Database Empty</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
