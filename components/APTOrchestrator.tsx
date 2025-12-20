
import React, { useState } from 'react';
import { APT_TACTICAL_CHAINS } from '../constants';
import { APTChain, TacticalStep } from '../types';
import { Target, Play, ShieldAlert, Cpu, Layers, Zap, Clock, TrendingUp, AlertTriangle } from 'lucide-react';

interface APTOrchestratorProps {
  onExecuteChain: (chain: APTChain) => void;
}

const APTOrchestrator: React.FC<APTOrchestratorProps> = ({ onExecuteChain }) => {
  const [activeChainId, setActiveChainId] = useState<string | null>(null);
  const [executingStep, setExecutingStep] = useState<string | null>(null);

  const selectedChain = APT_TACTICAL_CHAINS.find(c => c.id === activeChainId);

  const handleRun = (chain: APTChain) => {
    setActiveChainId(chain.id);
    // Simulate execution of steps
    setExecutingStep(chain.steps[0].id);
    onExecuteChain(chain);
  };

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-500">
      <header className="flex flex-col gap-1">
        <h2 className="text-xl font-black text-red-500 uppercase tracking-tighter flex items-center gap-3">
          <ShieldAlert size={20} /> APT Strategic Orchestrator
        </h2>
        <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Complex Tactical Chain Management</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 flex-1 overflow-hidden">
        {/* Chain Selector */}
        <div className="lg:col-span-4 space-y-4 overflow-y-auto pr-2">
          {APT_TACTICAL_CHAINS.map(chain => (
            <button
              key={chain.id}
              onClick={() => setActiveChainId(chain.id)}
              className={`w-full p-6 rounded-[2rem] border text-left transition-all relative overflow-hidden group
                ${activeChainId === chain.id ? 'bg-red-500/10 border-red-500/40 shadow-2xl' : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'}`}
            >
              <div className="flex justify-between items-start mb-4">
                 <div className={`p-3 rounded-2xl ${activeChainId === chain.id ? 'bg-red-500/20 text-red-400' : 'bg-black/40 text-slate-500'}`}>
                    <Layers size={20} />
                 </div>
                 <div className="flex items-center gap-1 text-[8px] font-black text-slate-500 uppercase border border-white/5 px-2 py-0.5 rounded">
                    Heat: <span className={chain.heatLevel > 40 ? 'text-red-500' : 'text-emerald-500'}>{chain.heatLevel}%</span>
                 </div>
              </div>
              <h4 className="text-xs font-black text-white uppercase tracking-tight">{chain.name}</h4>
              <p className="text-[10px] text-slate-600 mt-2 italic line-clamp-2">{chain.description}</p>
            </button>
          ))}
        </div>

        {/* Tactical Map */}
        <div className="lg:col-span-8 bg-black/40 border border-white/5 rounded-[3rem] p-10 flex flex-col overflow-hidden relative shadow-2xl">
          <div className="absolute top-0 right-0 p-12 opacity-5 pointer-events-none">
             <TrendingUp size={160} />
          </div>

          {selectedChain ? (
            <div className="h-full flex flex-col">
              <div className="flex justify-between items-start mb-10">
                <div>
                   <h3 className="text-xl font-black text-white uppercase tracking-tight">{selectedChain.name}</h3>
                   <div className="flex items-center gap-3 mt-2">
                      <span className="text-[10px] font-black text-blue-400 uppercase tracking-widest">Mimicry: {selectedChain.threatActorMimicry || 'Spectre-Native'}</span>
                      <div className="w-1.5 h-1.5 rounded-full bg-slate-800"></div>
                      <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">{selectedChain.steps.length} Strategic Steps</span>
                   </div>
                </div>
                <button 
                  onClick={() => handleRun(selectedChain)}
                  className="px-8 py-4 bg-red-600 hover:bg-red-500 text-white rounded-2xl text-[10px] font-black uppercase tracking-widest flex items-center gap-3 shadow-xl shadow-red-900/40 transition-all"
                >
                  <Play size={16} fill="currentColor" /> Execute Tactical Chain
                </button>
              </div>

              <div className="flex-1 space-y-4 overflow-y-auto pr-4 scrollbar-hide">
                {selectedChain.steps.map((step, idx) => (
                  <div 
                    key={step.id} 
                    className={`p-6 rounded-[2rem] border transition-all flex items-center justify-between relative
                      ${executingStep === step.id ? 'bg-red-500/5 border-red-500/40 scale-[1.02]' : 'bg-slate-900/40 border-slate-800 opacity-60'}`}
                  >
                    <div className="flex items-center gap-6">
                       <div className="text-xl font-black text-slate-700 w-8">{idx + 1}</div>
                       <div>
                          <h5 className="text-xs font-black text-slate-200 uppercase tracking-widest">{step.name}</h5>
                          <p className="text-[10px] font-mono text-slate-500 mt-1">{step.command}</p>
                       </div>
                    </div>

                    <div className="flex items-center gap-6">
                       <div className="flex flex-col items-end">
                          <span className="text-[8px] font-black text-slate-600 uppercase">Wait</span>
                          <span className="text-[10px] font-mono text-blue-400">{step.delay}ms</span>
                       </div>
                       <div className={`p-3 rounded-xl ${step.opsecRisk === 'High' ? 'text-red-500 bg-red-500/10' : 'text-emerald-500 bg-emerald-500/10'}`}>
                          <AlertTriangle size={16} />
                       </div>
                    </div>

                    {idx < selectedChain.steps.length - 1 && (
                      <div className="absolute -bottom-4 left-10 w-px h-4 bg-slate-800"></div>
                    )}
                  </div>
                ))}
              </div>

              <div className="mt-8 p-6 bg-red-500/5 border border-red-500/10 rounded-2xl flex items-start gap-4">
                 <Zap size={20} className="text-red-500 mt-1" />
                 <div className="space-y-1">
                    <h6 className="text-[10px] font-black text-red-400 uppercase">Strategic Forecast</h6>
                    <p className="text-[9px] text-slate-500 leading-relaxed italic">
                      "Executing this chain mimics the behavior of {selectedChain.threatActorMimicry || 'the Spectre group'}. Forensic analysis of logs will likely lead to misattribution if successful. Heat Level is manageable."
                    </p>
                 </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center opacity-20">
               <Target size={80} className="text-slate-600" />
               <p className="text-xs font-black uppercase tracking-[0.4em] mt-6">Select a Strategic Chain for Deployment</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default APTOrchestrator;
