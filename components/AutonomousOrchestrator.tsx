
import React, { useState } from 'react';
import { AutonomousRule, WinRMConnection } from '../types';
import { Cpu, Shield, Power, Activity, AlertTriangle, Zap, Target, Binary, Ghost } from 'lucide-react';

interface AutonomousOrchestratorProps {
  connections: WinRMConnection[];
}

const AutonomousOrchestrator: React.FC<AutonomousOrchestratorProps> = ({ connections }) => {
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);

  const mockRules: AutonomousRule[] = [
    { id: 'r1', trigger: 'SignalLoss', action: 'Migrate', params: { target: 'explorer.exe', wait: '2h' } },
    { id: 'r2', trigger: 'EDRAlert', action: 'SelfTerminate', params: { secureWipe: true } }
  ];

  const agent = connections.find(c => c.id === selectedAgentId);

  return (
    <div className="h-full flex flex-col gap-8 animate-in fade-in duration-500">
      <header className="flex flex-col gap-1">
        <h2 className="text-2xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-3">
          <Ghost size={24} /> Autonomous Overlord Routine
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-black tracking-[0.2em] mt-1">Configure Edge Intelligence & "Dead Man" Persistence Logic</p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 overflow-hidden">
        {/* Agent Selection */}
        <div className="lg:col-span-4 flex flex-col gap-4 overflow-y-auto pr-2">
          {connections.map(c => (
            <button 
              key={c.id}
              onClick={() => setSelectedAgentId(c.id)}
              className={`w-full p-6 rounded-[2rem] border text-left transition-all relative overflow-hidden group
                ${selectedAgentId === c.id ? 'bg-emerald-500/10 border-emerald-500/40' : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'}`}
            >
              <div className="flex justify-between items-start mb-4">
                 <div className={`p-3 rounded-2xl ${selectedAgentId === c.id ? 'bg-emerald-500/20 text-emerald-400' : 'bg-black/40 text-slate-500'}`}>
                    <Cpu size={20} />
                 </div>
                 <div className={`w-2 h-2 rounded-full ${c.status === 'connected' ? 'bg-emerald-500' : 'bg-slate-700'}`}></div>
              </div>
              <h4 className="text-xs font-black text-white uppercase tracking-tight">{c.host}</h4>
              <p className="text-[10px] text-slate-600 mt-1 uppercase font-black tracking-widest">{c.agentType}</p>
              
              <div className="mt-4 flex gap-2">
                 <span className="text-[8px] font-black text-emerald-500/50 uppercase border border-emerald-500/10 px-2 py-0.5 rounded">2 Active Rules</span>
              </div>
            </button>
          ))}
        </div>

        {/* Rule Editor */}
        <div className="lg:col-span-8 flex flex-col gap-6">
          {agent ? (
            <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-10 flex flex-col relative overflow-hidden shadow-2xl h-full">
              <div className="absolute top-0 right-0 p-10 opacity-5">
                 <Binary size={120} />
              </div>

              <div className="flex justify-between items-start mb-10">
                <div>
                  <h3 className="text-xl font-black text-white uppercase tracking-tight">Agent Tactical Brain: {agent.host}</h3>
                  <p className="text-xs text-slate-500 mt-2">Configure behavioral responses to local environmental changes.</p>
                </div>
                <button className="px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl text-[10px] font-black uppercase tracking-widest flex items-center gap-2 shadow-xl shadow-emerald-900/40 transition-all">
                   <Zap size={14} /> Synchronize Logic
                </button>
              </div>

              <div className="space-y-6 flex-1 overflow-y-auto pr-4 scrollbar-hide">
                 {mockRules.map(rule => (
                   <div key={rule.id} className="p-8 bg-black/40 border border-white/5 rounded-3xl relative group">
                      <div className="flex justify-between items-center mb-6">
                         <div className="flex items-center gap-4">
                            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                               <Shield size={18} />
                            </div>
                            <div>
                               <h5 className="text-xs font-black text-slate-200 uppercase tracking-widest">{rule.trigger} Handler</h5>
                               <p className="text-[9px] text-slate-600 uppercase mt-0.5">Automated Edge Action</p>
                            </div>
                         </div>
                         <button className="text-slate-800 hover:text-red-400 transition-colors">
                            <AlertTriangle size={16} />
                         </button>
                      </div>

                      <div className="grid grid-cols-2 gap-8">
                         <div className="space-y-1">
                            <label className="text-[8px] font-black text-slate-500 uppercase tracking-[0.2em]">Autonomous Action</label>
                            <div className="p-3 bg-slate-900 rounded-xl text-xs font-mono text-emerald-400 border border-white/5 uppercase">
                               {rule.action}
                            </div>
                         </div>
                         <div className="space-y-1">
                            <label className="text-[8px] font-black text-slate-500 uppercase tracking-[0.2em]">Active Parameters</label>
                            <div className="flex flex-wrap gap-2">
                               {Object.entries(rule.params).map(([k, v]) => (
                                 <span key={k} className="text-[9px] font-mono text-blue-400 bg-blue-500/5 px-2 py-1 rounded border border-blue-500/10 uppercase">
                                   {k}: {String(v)}
                                 </span>
                               ))}
                            </div>
                         </div>
                      </div>
                   </div>
                 ))}
                 
                 <button className="w-full py-6 border-2 border-dashed border-slate-800 rounded-3xl text-slate-600 hover:text-emerald-500 hover:border-emerald-500/30 transition-all flex items-center justify-center gap-2 text-[10px] font-black uppercase tracking-widest">
                    <Power size={14} /> Inject New Edge Logic Rule
                 </button>
              </div>

              <div className="mt-8 pt-8 border-t border-white/5">
                 <div className="flex items-start gap-4 p-4 bg-emerald-500/5 border border-emerald-500/10 rounded-2xl">
                    <Activity size={18} className="text-emerald-500 mt-1 shrink-0" />
                    <p className="text-[9px] text-emerald-500/60 leading-relaxed italic uppercase font-black tracking-tighter">
                      OpSec Note: Autonomous rules execute entirely within the memory space of the remote agent. No telemetry is sent to the Spectre Core during execution until signal is re-established.
                    </p>
                 </div>
              </div>
            </section>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-slate-700 opacity-20 bg-slate-900/10 border border-slate-800 border-dashed rounded-[3rem]">
               <Cpu size={80} className="mb-4" />
               <p className="text-xs font-black uppercase tracking-[0.4em]">Select an Agent to Program Edge Logic</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AutonomousOrchestrator;
