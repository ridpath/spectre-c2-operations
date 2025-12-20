
import React, { useState } from 'react';
import { Shield, Lock, Key, Cpu, Wifi, Zap, Terminal as TerminalIcon, ShieldCheck } from 'lucide-react';

interface LoginScreenProps {
  onLogin: (alias: string) => void;
}

const LoginScreen: React.FC<LoginScreenProps> = ({ onLogin }) => {
  const [alias, setAlias] = useState('');
  const [passkey, setPasskey] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);

  const handleEntry = (e: React.FormEvent) => {
    e.preventDefault();
    if (!alias) return;
    setIsVerifying(true);
    // Simulate tactical handshake
    setTimeout(() => {
      onLogin(alias);
      setIsVerifying(false);
    }, 2000);
  };

  return (
    <div className="fixed inset-0 bg-[#020617] flex items-center justify-center z-[100] p-6 overflow-hidden">
      {/* Background Data Streams */}
      <div className="absolute inset-0 opacity-5 pointer-events-none font-mono text-[8px] overflow-hidden whitespace-pre">
        {Array.from({ length: 100 }).map((_, i) => (
          <div key={i} className="animate-pulse" style={{ animationDelay: `${i * 0.1}s` }}>
            {Math.random().toString(16).repeat(10)}
            {Math.random() > 0.5 ? ' LOCK_ENGAGED ' : ' SIGNAL_BROKER_UP '}
            {Math.random().toString(16).repeat(10)}
          </div>
        ))}
      </div>

      <div className="w-full max-w-md relative">
        <div className="absolute -inset-1 bg-gradient-to-r from-emerald-500 to-blue-500 rounded-[3rem] blur opacity-20 animate-pulse"></div>
        
        <div className="relative bg-[#0b1120] border border-white/10 rounded-[2.5rem] p-12 shadow-2xl flex flex-col items-center">
          <div className="w-20 h-20 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mb-8 relative">
             <div className="absolute inset-0 rounded-full border border-emerald-500/40 animate-ping opacity-20"></div>
             <Shield className="text-emerald-500" size={32} />
          </div>

          <header className="text-center mb-10">
            <h1 className="text-2xl font-black text-white uppercase tracking-tighter">Spectre C2 Gateway</h1>
            <p className="text-[10px] text-slate-500 font-black uppercase tracking-[0.4em] mt-2">Team Operational Logic v4.1</p>
          </header>

          <form onSubmit={handleEntry} className="w-full space-y-6">
            <div className="space-y-2">
               <label className="text-[9px] font-black text-slate-500 uppercase tracking-widest px-1">Operator Alias</label>
               <div className="relative">
                 <TerminalIcon size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" />
                 <input 
                  required
                  value={alias}
                  onChange={e => setAlias(e.target.value)}
                  className="w-full bg-black/60 border border-slate-800 rounded-2xl py-4 pl-12 pr-6 text-sm font-mono text-emerald-400 focus:border-emerald-500 transition-all outline-none" 
                  placeholder="e.g. SPECTRE-01"
                 />
               </div>
            </div>

            <div className="space-y-2">
               <label className="text-[9px] font-black text-slate-500 uppercase tracking-widest px-1">Mission Keycard</label>
               <div className="relative">
                 <Key size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" />
                 <input 
                  type="password"
                  value={passkey}
                  onChange={e => setPasskey(e.target.value)}
                  className="w-full bg-black/60 border border-slate-800 rounded-2xl py-4 pl-12 pr-6 text-sm font-mono text-slate-500 focus:border-blue-500 transition-all outline-none" 
                  placeholder="••••••••••••"
                 />
               </div>
            </div>

            <button 
              disabled={isVerifying || !alias}
              className="w-full py-5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-30 text-white rounded-2xl text-[11px] font-black uppercase tracking-[0.2em] transition-all shadow-xl shadow-emerald-900/40 flex items-center justify-center gap-3 active:scale-95"
            >
              {isVerifying ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                  Authenticating Handshake...
                </>
              ) : (
                <>
                  <Lock size={16} /> Establish Operator Session
                </>
              )}
            </button>
          </form>

          <footer className="mt-12 flex items-center gap-6 opacity-30">
            <div className="flex items-center gap-2">
               <Cpu size={12} />
               <span className="text-[8px] font-black uppercase tracking-widest">AES-256</span>
            </div>
            <div className="flex items-center gap-2">
               <Wifi size={12} />
               <span className="text-[8px] font-black uppercase tracking-widest">TLS 1.3</span>
            </div>
            <div className="flex items-center gap-2">
               <ShieldCheck size={12} />
               <span className="text-[8px] font-black uppercase tracking-widest">EDR-STLS</span>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
};

export default LoginScreen;
