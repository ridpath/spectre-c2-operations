import React, { useState, useEffect } from 'react';
import { Sparkles, Database } from 'lucide-react';
import { demoModeService } from '../services/demoModeService';

export default function DemoModeToggle() {
  const [isDemoMode, setIsDemoMode] = useState(demoModeService.getDemoMode());

  useEffect(() => {
    const unsubscribe = demoModeService.subscribe((isDemo) => {
      setIsDemoMode(isDemo);
    });
    return unsubscribe;
  }, []);

  const handleToggle = () => {
    demoModeService.setDemoMode(!isDemoMode);
  };

  return (
    <div className="flex flex-col items-end">
      <span className="text-[8px] font-black text-slate-500 uppercase tracking-widest">Data Mode</span>
      <button
        onClick={handleToggle}
        className={`flex items-center gap-2 px-3 py-1 rounded-lg border transition-all ${
          isDemoMode
            ? 'bg-purple-500/10 border-purple-500/30 text-purple-400 hover:bg-purple-500/20'
            : 'bg-slate-800 border-white/5 text-emerald-500 hover:bg-slate-700'
        }`}
        title={isDemoMode ? 'Showing demo data' : 'Showing real backend data'}
      >
        {isDemoMode ? <Sparkles size={12} /> : <Database size={12} />}
        <span className="text-[10px] font-black uppercase tracking-widest">
          {isDemoMode ? 'DEMO' : 'LIVE'}
        </span>
      </button>
    </div>
  );
}
