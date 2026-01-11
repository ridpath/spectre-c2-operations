
import React, { useState } from 'react';
import { Shield, Search, Terminal as TerminalIcon, Download, Zap, Box, Lock, UserCheck } from 'lucide-react';
import { PENTEST_TOOLS } from '../constants';

interface ArmoryProps {
  onInsertCode: (code: string) => void;
}

const Armory: React.FC<ArmoryProps> = ({ onInsertCode }) => {
  const [filter, setFilter] = useState('all');

  const categories = [
    { id: 'all', label: 'All Gear', icon: <Box size={14} /> },
    { id: 'enumeration', label: 'Recon', icon: <Search size={14} /> },
    { id: 'credentials', label: 'Access', icon: <Lock size={14} /> },
    { id: 'privesc', label: 'Escalation', icon: <Zap size={14} /> },
    { id: 'persistence', label: 'Persistence', icon: <UserCheck size={14} /> },
  ];

  return (
    <div className="flex flex-col h-full gap-6 animate-in fade-in duration-700">
      <header className="flex justify-between items-end">
        <div>
          <h2 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-3">
            <Shield size={24} className="text-blue-500" /> Tactical Armory
          </h2>
          <p className="text-[10px] text-slate-500 uppercase tracking-[0.3em] font-bold mt-1">Professional Offensive Tooling</p>
        </div>
        <div className="flex bg-slate-900/50 p-1 rounded-xl border border-white/5">
          {categories.map(cat => (
            <button 
              key={cat.id}
              onClick={() => setFilter(cat.id)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg text-[10px] font-black uppercase transition-all ${
                filter === cat.id ? 'bg-blue-600 text-white shadow-lg shadow-blue-900/40' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              {cat.icon} {cat.label}
            </button>
          ))}
        </div>
      </header>

      <div className="flex-1 overflow-y-auto pr-2 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pb-20 scrollbar-hide">
        {PENTEST_TOOLS.filter(t => filter === 'all' || t.category === filter).map(tool => (
          <div key={tool.id} className="bg-slate-900/40 border border-slate-800 rounded-[2rem] p-6 hover:border-blue-500/40 transition-all group relative overflow-hidden flex flex-col">
            <div className="absolute top-0 right-0 p-8 opacity-[0.03] group-hover:opacity-[0.08] transition-opacity">
               <Shield size={80} />
            </div>
            
            <div className="flex justify-between items-start mb-4 relative z-10">
              <div className="p-3 bg-black/40 border border-white/5 rounded-2xl text-blue-400 group-hover:scale-110 transition-transform">
                <Box size={20} />
              </div>
              <div className="flex gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                 <button onClick={() => onInsertCode(`load-module ${tool.id}`)} className="p-2.5 bg-blue-600 text-white rounded-xl shadow-lg">
                    <TerminalIcon size={14} />
                 </button>
              </div>
            </div>

            <h3 className="text-sm font-black text-white uppercase tracking-tight mb-2">{tool.name}</h3>
            <p className="text-[10px] text-slate-500 italic leading-relaxed mb-6 flex-1">{tool.description}</p>
            
            <div className="space-y-3 mt-auto">
               <div className="flex items-center justify-between text-[8px] font-black uppercase tracking-widest text-slate-600">
                  <span>OpSec Risk</span>
                  <span className={tool.type === 'ps1' ? 'text-yellow-500' : 'text-emerald-500'}>
                    {tool.type === 'ps1' ? 'Medium' : 'Low'}
                  </span>
               </div>
               <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
                  <div className={`h-full ${tool.type === 'ps1' ? 'bg-yellow-500 w-1/2' : 'bg-emerald-500 w-1/4'}`}></div>
               </div>
               <div className="flex gap-2 mt-4">
                  <span className="text-[8px] font-black px-2 py-0.5 bg-black/40 text-blue-400 rounded border border-blue-400/20 uppercase">{tool.category}</span>
                  <span className="text-[8px] font-black px-2 py-0.5 bg-black/40 text-slate-500 rounded border border-white/5 uppercase">{tool.type}</span>
               </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Armory;
