
import React from 'react';
import { C2Listener } from '../types';
import { Plus, Radio, Power, Trash2, Globe, Server } from 'lucide-react';

interface ListenerManagerProps {
  listeners: C2Listener[];
  setListeners: React.Dispatch<React.SetStateAction<C2Listener[]>>;
}

const ListenerManager: React.FC<ListenerManagerProps> = ({ listeners, setListeners }) => {
  const toggleListener = (id: string) => {
    setListeners(prev => prev.map(l => l.id === id ? { ...l, active: !l.active } : l));
  };

  const removeListener = (id: string) => {
    setListeners(prev => prev.filter(l => l.id !== id));
  };

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4">
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-black uppercase tracking-tighter text-slate-100 flex items-center gap-3">
            <Radio size={28} className="text-emerald-400" /> C2 Listeners
          </h2>
          <p className="text-xs text-slate-500 mt-1 uppercase tracking-widest">Inbound management for remote agents.</p>
        </div>
        <button className="px-6 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-full text-xs font-black transition-all flex items-center gap-2 shadow-xl shadow-emerald-900/20">
          <Plus size={16} /> New Listener
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {listeners.map(listener => (
          <div key={listener.id} className={`p-6 bg-slate-900/40 border rounded-3xl transition-all ${listener.active ? 'border-emerald-500/30' : 'border-slate-800 opacity-60'}`}>
            <div className="flex justify-between items-start mb-6">
              <div className="flex items-center gap-3">
                <div className={`p-3 rounded-2xl ${listener.active ? 'bg-emerald-500/10 text-emerald-400' : 'bg-slate-800 text-slate-500'}`}>
                  {listener.type === 'http' ? <Globe size={20} /> : <Server size={20} />}
                </div>
                <div>
                  <h4 className="text-sm font-black text-slate-100 uppercase tracking-tight">{listener.name}</h4>
                  <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest">{listener.type} PROTOCOL</span>
                </div>
              </div>
              <div className="flex gap-2">
                <button 
                  onClick={() => toggleListener(listener.id)}
                  className={`p-2 rounded-xl transition-all ${listener.active ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-900/30' : 'bg-slate-800 text-slate-500'}`}
                >
                  <Power size={14} />
                </button>
                <button 
                  onClick={() => removeListener(listener.id)}
                  className="p-2 bg-slate-800 text-slate-500 hover:text-red-400 rounded-xl transition-all"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <div className="text-[8px] font-black text-slate-600 uppercase tracking-widest">Interface (LHOST)</div>
                <div className="text-xs font-mono text-slate-300 bg-black/40 p-2 rounded-lg border border-white/5">{listener.lhost}</div>
              </div>
              <div className="space-y-1">
                <div className="text-[8px] font-black text-slate-600 uppercase tracking-widest">Port (LPORT)</div>
                <div className="text-xs font-mono text-slate-300 bg-black/40 p-2 rounded-lg border border-white/5">{listener.lport}</div>
              </div>
            </div>

            <div className="mt-6 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${listener.active ? 'bg-emerald-500 animate-pulse' : 'bg-slate-700'}`}></div>
                <span className={`text-[10px] font-black uppercase ${listener.active ? 'text-emerald-500' : 'text-slate-600'}`}>
                  {listener.active ? 'Listening' : 'Idle'}
                </span>
              </div>
              <div className="text-[9px] text-slate-600 font-mono">ID: {listener.id.toUpperCase()}</div>
            </div>
          </div>
        ))}

        {listeners.length === 0 && (
          <div className="md:col-span-2 py-20 bg-slate-900/20 border border-dashed border-slate-800 rounded-3xl flex flex-col items-center justify-center opacity-40">
            <Radio size={48} className="text-slate-600 mb-4" />
            <p className="text-xs font-black uppercase tracking-widest text-slate-500">No active listeners configured</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default ListenerManager;
