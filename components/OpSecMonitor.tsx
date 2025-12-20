
import React, { useEffect, useState } from 'react';
import { Activity, ShieldAlert, Zap, Cpu, Bell, Signal, AlertTriangle } from 'lucide-react';
import { WinRMConnection } from '../types';

interface OpSecMonitorProps {
  connections: WinRMConnection[];
}

const OpSecMonitor: React.FC<OpSecMonitorProps> = ({ connections }) => {
  const [totalEntropy, setTotalEntropy] = useState(14);
  const [alerts, setAlerts] = useState<string[]>([]);

  useEffect(() => {
    const avg = connections.reduce((acc, c) => acc + c.entropy, 0) / (connections.length || 1);
    setTotalEntropy(avg);
    
    if (avg > 50) setAlerts(prev => [...prev.slice(-4), "Warning: High Spectral Entropy Detected"]);
  }, [connections]);

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-500">
      <header className="flex flex-col gap-1">
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-3">
          <ShieldAlert size={20} /> Operational SIGINT HUD
        </h2>
        <p className="text-[10px] text-slate-500 uppercase tracking-widest font-black mt-1">Real-time Signature & Noise Analysis</p>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-slate-900/40 border border-slate-800 p-8 rounded-[2.5rem] flex flex-col gap-4 relative overflow-hidden group">
          <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Fleet Entropy</span>
          <div className="flex items-end gap-3">
             <span className={`text-4xl font-black transition-colors ${totalEntropy > 50 ? 'text-red-500' : 'text-emerald-500'}`}>{Math.floor(totalEntropy)}%</span>
             <Activity size={18} className={totalEntropy > 50 ? 'text-red-500 animate-pulse' : 'text-emerald-500'} />
          </div>
          <div className="w-full h-1 bg-slate-800 rounded-full mt-2">
             <div className={`h-full transition-all duration-1000 ${totalEntropy > 50 ? 'bg-red-500 shadow-[0_0_10px_red]' : 'bg-emerald-500 shadow-[0_0_10px_#10b981]'}`} style={{ width: `${totalEntropy}%` }}></div>
          </div>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-8 rounded-[2.5rem] flex flex-col gap-4">
          <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Active Links</span>
          <div className="flex items-end gap-3 text-white">
             <span className="text-4xl font-black">{connections.length}</span>
             <Signal size={18} className="text-blue-500" />
          </div>
          <p className="text-[9px] text-slate-600 font-bold uppercase tracking-tighter">Distributed Signal Quality: High</p>
        </div>

        <div className="bg-slate-900/40 border border-slate-800 p-8 rounded-[2.5rem] flex flex-col gap-4">
          <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Counter-Intel State</span>
          <div className="flex items-center gap-3">
             <div className="w-3 h-3 rounded-full bg-emerald-500 shadow-[0_0_10px_#10b981]"></div>
             <span className="text-xs font-black text-white uppercase">Sovereign Mode</span>
          </div>
          <p className="text-[9px] text-slate-600 font-bold uppercase tracking-tighter">Agents executing autonomous logic: 2</p>
        </div>
      </div>

      <div className="flex-1 bg-black/40 border border-white/5 rounded-[3rem] p-10 flex flex-col overflow-hidden">
        <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] mb-6 flex items-center gap-2">
           <Bell size={14} className="text-yellow-500" /> Strategic Operational Log
        </h3>
        
        <div className="flex-1 overflow-y-auto space-y-4 pr-4 scrollbar-hide font-mono text-[10px]">
           {alerts.length === 0 && (
             <div className="h-full flex flex-col items-center justify-center opacity-10">
                <AlertTriangle size={64} />
                <p className="mt-4 font-black uppercase tracking-widest">No Priority Alerts</p>
             </div>
           )}
           {alerts.map((alert, i) => (
             <div key={i} className="flex gap-4 p-4 bg-red-500/5 border border-red-500/10 rounded-2xl animate-in slide-in-from-left-4">
                <span className="text-red-500 shrink-0 mt-0.5">[{new Date().toLocaleTimeString()}]</span>
                <span className="text-slate-300 uppercase font-bold tracking-tight">{alert}</span>
             </div>
           ))}
           <div className="p-4 bg-blue-500/5 border border-blue-500/10 rounded-2xl flex gap-4">
              <span className="text-blue-500">[{new Date().toLocaleTimeString()}]</span>
              <span className="text-slate-500 uppercase">Mesh signal synchronization successful across DC01.HTB.LOCAL</span>
           </div>
        </div>
      </div>
    </div>
  );
};

export default OpSecMonitor;
