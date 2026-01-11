
import React, { useState } from 'react';
import { OFFENSIVE_REGISTRY } from '../constants';
import { OffensiveModule, WinRMConnection } from '../types';
import { Search, Shield, Zap, Terminal, Filter, Box, UserCheck, AlertTriangle } from 'lucide-react';

interface ModuleBrowserProps {
  activeConnection: WinRMConnection | null;
  onTaskModule: (command: string) => void;
}

const ModuleBrowser: React.FC<ModuleBrowserProps> = ({ activeConnection, onTaskModule }) => {
  const [filter, setFilter] = useState<string>('All');
  const [search, setSearch] = useState('');

  const filteredModules = OFFENSIVE_REGISTRY.filter(m => {
    const matchesCategory = filter === 'All' || m.category === filter;
    const matchesSearch = search === '' || 
      m.name.toLowerCase().includes(search.toLowerCase()) || 
      m.description.toLowerCase().includes(search.toLowerCase());
    return matchesCategory && matchesSearch;
  });

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-500">
      <header className="flex justify-between items-end">
        <div>
          <h2 className="text-xl font-black text-white uppercase tracking-tighter flex items-center gap-3">
            <Box size={20} className="text-emerald-500" /> Capability Engine
          </h2>
          <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest mt-1">Modular Post-Exploitation Orchestrator</p>
        </div>
        <div className="flex gap-2 bg-black/40 p-1 rounded-xl border border-white/5">
          {['All', 'Recon', 'Exploitation', 'Post-Ex', 'Persistence'].map(cat => (
            <button 
              key={cat}
              onClick={() => setFilter(cat)}
              className={`px-3 py-1.5 rounded-lg text-[9px] font-black uppercase transition-all ${
                filter === cat ? 'bg-emerald-600 text-white' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {cat === 'Post-Ex' ? 'Post-Ex' : cat}
            </button>
          ))}
        </div>
      </header>

      <div className="relative">
        <Search size={14} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" />
        <input 
          placeholder="Search offensive modules..." 
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="w-full bg-slate-900/50 border border-slate-800 rounded-2xl py-3 pl-10 pr-4 text-xs font-mono outline-none focus:border-emerald-500 transition-all"
        />
      </div>

      <div className="flex-1 overflow-y-auto pr-2 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pb-20 scrollbar-hide">
        {filteredModules.map(module => {
          const isCompatible = activeConnection ? 
            (module.requiredIntegrity === 'User' || activeConnection.integrityLevel === module.requiredIntegrity || activeConnection.integrityLevel === 'SYSTEM') : true;

          return (
            <div 
              key={module.id} 
              className={`bg-slate-900/40 border rounded-[2rem] p-6 flex flex-col transition-all group relative overflow-hidden ${
                isCompatible ? 'border-slate-800 hover:border-emerald-500/40' : 'border-red-900/20 opacity-50 grayscale'
              }`}
            >
              <div className="flex justify-between items-start mb-4">
                <div className="p-2.5 rounded-2xl bg-black/40 text-emerald-400">
                   <Zap size={18} />
                </div>
                {!isCompatible && (
                  <div className="flex items-center gap-1 text-red-500" title="Integrity Level Mismatch">
                    <Shield size={14} />
                    <span className="text-[8px] font-black uppercase">Elevation Required</span>
                  </div>
                )}
              </div>

              <h3 className="text-xs font-black text-white uppercase tracking-tight mb-2">{module.name}</h3>
              <p className="text-[10px] text-slate-500 italic mb-6 leading-relaxed flex-1">{module.description}</p>
              
              <div className="space-y-4">
                <div className="flex justify-between items-center text-[8px] font-black uppercase text-slate-600">
                  <span>OpSec Risk: <span className={module.opsecRisk === 'High' ? 'text-red-500' : 'text-emerald-500'}>{module.opsecRisk}</span></span>
                  <span>Noise: {module.noiseLevel}/10</span>
                </div>
                
                <div className="flex flex-wrap gap-1.5">
                  {module.commands.map(cmd => (
                    <button 
                      key={cmd.trigger}
                      disabled={!isCompatible}
                      onClick={() => onTaskModule(cmd.trigger)}
                      className="px-2.5 py-1.5 bg-black/40 border border-white/5 rounded-lg text-[9px] font-mono text-emerald-500 hover:bg-emerald-500 hover:text-white transition-all"
                    >
                      {cmd.trigger}
                    </button>
                  ))}
                </div>
              </div>

              <div className="absolute bottom-0 right-0 p-4 opacity-[0.03] group-hover:opacity-[0.08] transition-opacity">
                 <AlertTriangle size={60} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ModuleBrowser;
