
import React, { useState, useEffect } from 'react';
import { 
  Globe, 
  Shield, 
  Wifi, 
  Layers, 
  Cpu, 
  Zap, 
  Cloud, 
  Github, 
  MessageSquare, 
  Clock, 
  Activity, 
  Lock, 
  Settings2,
  Video,
  AlertTriangle,
  Radio,
  Unplug
} from 'lucide-react';

type ProfileType = 'Office365' | 'AWS' | 'GitHub' | 'Slack' | 'GoogleWorkspace' | 'Zoom' | 'PhantomVector';

const SpectrumStudio: React.FC = () => {
  const [activeProfile, setActiveProfile] = useState<ProfileType>('Office365');
  const [isLive, setIsLive] = useState(true);
  const [jitterFactor, setJitterFactor] = useState(45);
  const [entropy, setEntropy] = useState(12);
  const [activeTab, setActiveTab] = useState<'shaping' | 'fragmentation' | 'temporal'>('shaping');

  const mimicryDetails: Record<ProfileType, { icon: any, color: string, desc: string, risk: string, protocol: string }> = {
    'Office365': { icon: <Cloud size={32} />, color: 'blue', desc: 'Mimics Outlook/SharePoint web-socket traffic.', risk: 'Low', protocol: 'HTTPS/2' },
    'AWS': { icon: <Layers size={32} />, color: 'orange', desc: 'Mimics S3 API calls and EC2 telemetry.', risk: 'Medium', protocol: 'HTTPS/1.1' },
    'GitHub': { icon: <Github size={32} />, color: 'emerald', desc: 'Mimics Git-over-HTTPS and Action runners.', risk: 'Low', protocol: 'HTTPS/TLS1.3' },
    'Slack': { icon: <MessageSquare size={32} />, color: 'purple', desc: 'Mimics persistent RTM socket connections.', risk: 'Low', protocol: 'WSS (WebSockets)' },
    'GoogleWorkspace': { icon: <Globe size={32} />, color: 'red', desc: 'Mimics gRPC-based Drive synchronization.', risk: 'Low', protocol: 'HTTP/3 (QUIC)' },
    'Zoom': { icon: <Video size={32} />, color: 'blue', desc: 'Masks C2 within WebRTC / UDP media streams.', risk: 'Ultra-Low', protocol: 'UDP/SRTP' },
    'PhantomVector': { icon: <Radio size={32} />, color: 'red', desc: 'Industrialized vector-based protocol mimicry.', risk: 'Elite', protocol: 'VECTORIZED/RAW' }
  };

  useEffect(() => {
    if (!isLive) return;
    const interval = setInterval(() => {
      setEntropy(prev => {
        const noise = Math.sin(Date.now() / 1500) * 5;
        return Math.max(2, Math.min(25, 10 + noise));
      });
    }, 100);
    return () => clearInterval(interval);
  }, [isLive]);

  return (
    <div className="h-full flex flex-col gap-8 animate-in fade-in duration-700">
      <header className="flex justify-between items-start">
        <div className="flex flex-col gap-1">
          <h2 className="text-2xl font-black text-blue-400 uppercase tracking-tighter flex items-center gap-3">
            <Wifi size={24} /> Spectrum Mimicry & Shaping
          </h2>
          <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-black mt-1">Industrial-Grade Behavioral Signal Orchestration</p>
        </div>
        
        <div className="flex items-center gap-4 bg-slate-900/60 p-2 rounded-2xl border border-white/5 shadow-2xl">
           <div className="flex flex-col items-end px-4 border-r border-white/10">
              <span className="text-[8px] font-black text-slate-600 uppercase tracking-widest">Spectral Integrity</span>
              <span className={`text-xs font-mono font-bold ${entropy > 18 ? 'text-yellow-500' : 'text-emerald-500'}`}>{entropy.toFixed(2)}% Deviance</span>
           </div>
           <button 
            onClick={() => setIsLive(!isLive)}
            className={`px-5 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all shadow-lg ${isLive ? 'bg-emerald-600 text-white shadow-emerald-900/20' : 'bg-slate-800 text-slate-500'}`}
           >
             {isLive ? 'Analyzer Active' : 'Sensor Standby'}
           </button>
        </div>
      </header>

      <div className="flex gap-4 overflow-x-auto scrollbar-hide pb-2">
        {(Object.keys(mimicryDetails) as ProfileType[]).map(type => (
          <button 
            key={type}
            onClick={() => setActiveProfile(type)}
            className={`flex-shrink-0 w-52 p-6 rounded-[2.5rem] border transition-all text-left flex flex-col gap-5 relative overflow-hidden group
              ${activeProfile === type ? 'bg-blue-500/10 border-blue-500/40 shadow-2xl scale-[1.02]' : 'bg-slate-900/40 border-slate-800 opacity-60 hover:opacity-100'}`}
          >
            <div className={`p-4 rounded-3xl w-fit ${activeProfile === type ? 'bg-blue-500/20 text-blue-400 shadow-xl' : 'bg-black/40 text-slate-500'}`}>
              {mimicryDetails[type].icon}
            </div>
            <div>
               <h4 className="text-xs font-black text-white uppercase tracking-tight">{type}</h4>
               <p className="text-[9px] text-slate-500 mt-1 uppercase font-black tracking-widest">{mimicryDetails[type].protocol}</p>
            </div>
            {activeProfile === type && <div className="absolute top-4 right-4 w-2 h-2 rounded-full bg-blue-500 animate-ping"></div>}
          </button>
        ))}
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 overflow-hidden">
        <div className="lg:col-span-4 flex flex-col gap-6 overflow-y-auto scrollbar-hide">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 space-y-8 shadow-2xl h-full flex flex-col">
            <div className="flex bg-black/40 p-1.5 rounded-2xl border border-white/10 shadow-inner">
              <button 
                onClick={() => setActiveTab('shaping')}
                className={`flex-1 py-2 text-[9px] font-black uppercase rounded-xl transition-all ${activeTab === 'shaping' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
              >Jitter</button>
              <button 
                onClick={() => setActiveTab('fragmentation')}
                className={`flex-1 py-2 text-[9px] font-black uppercase rounded-xl transition-all ${activeTab === 'fragmentation' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
              >Vector</button>
              <button 
                onClick={() => setActiveTab('temporal')}
                className={`flex-1 py-2 text-[9px] font-black uppercase rounded-xl transition-all ${activeTab === 'temporal' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
              >Temporal</button>
            </div>

            <div className="flex-1 space-y-10">
              {activeTab === 'shaping' && (
                <div className="space-y-8 animate-in slide-in-from-left-4 duration-300">
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Signal Jitter</label>
                      <span className="text-xs font-mono text-blue-400">{jitterFactor}% Burst</span>
                    </div>
                    <input 
                      type="range" min="5" max="95" value={jitterFactor} 
                      onChange={e => setJitterFactor(parseInt(e.target.value))}
                      className="w-full h-1 bg-slate-800 rounded-full appearance-none accent-blue-500 shadow-inner"
                    />
                    <p className="text-[9px] text-slate-600 leading-relaxed uppercase font-black tracking-tight italic">
                      Randomizes beacon intervals to neutralize behavioral analytic triggers in EDR/XDR environments.
                    </p>
                  </div>

                  <div className="h-px bg-white/5"></div>

                  <div className="space-y-4">
                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] flex items-center gap-2">
                      <Shield size={14} className="text-emerald-500" /> Stealth Modules
                    </span>
                    <div className="grid grid-cols-2 gap-2">
                      {['MTU Masking', 'TCP Overlap', 'HTTP/3 QUIC', 'Signal Multiplex'].map(m => (
                        <button key={m} className="p-4 bg-black/40 border border-white/5 rounded-2xl text-[9px] font-black text-slate-500 text-left hover:border-blue-500/30 hover:text-white transition-all">
                          {m}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'fragmentation' && (
                <div className="space-y-8 animate-in slide-in-from-left-4 duration-300">
                  <div className="bg-red-500/5 border border-red-500/20 p-5 rounded-[1.5rem] flex items-start gap-4">
                    <AlertTriangle size={18} className="text-red-400 mt-1 shrink-0" />
                    <p className="text-[10px] text-red-400/80 leading-relaxed font-black uppercase tracking-tight">
                      Fragmented vectors are designed for government-lab testing. May trigger reassembly alerts in high-security gateways.
                    </p>
                  </div>
                  
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                       <span className="text-[10px] font-black text-slate-400 uppercase">Packet Fragmentation</span>
                       <span className="text-[10px] font-mono text-red-400">128-512B Blocks</span>
                    </div>
                    <div className="flex items-center justify-between p-5 bg-black/60 rounded-2xl border border-white/5 shadow-inner">
                      <div className="flex flex-col gap-1">
                        <span className="text-xs text-slate-200 uppercase font-black">Multi-Vector Transmit</span>
                        <span className="text-[8px] text-slate-600 uppercase font-black">Round-robin protocol egress</span>
                      </div>
                      <div className="w-12 h-6 bg-emerald-600 rounded-full relative">
                        <div className="absolute right-1 top-1 w-4 h-4 bg-white rounded-full shadow-lg"></div>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'temporal' && (
                <div className="space-y-8 animate-in slide-in-from-left-4 duration-300">
                  <div className="flex items-center gap-5 p-6 bg-blue-500/10 border border-blue-500/20 rounded-[1.5rem] shadow-xl">
                    <Clock size={24} className="text-blue-400" />
                    <div>
                      <h5 className="text-[11px] font-black text-white uppercase tracking-widest">Chronos Simulator</h5>
                      <p className="text-[9px] text-slate-500 uppercase font-black tracking-tight mt-1">Activity Scaling via Target Workday</p>
                    </div>
                  </div>
                  <div className="p-6 bg-black/40 border border-white/5 rounded-[1.5rem] space-y-6">
                     <div className="flex justify-between items-center text-[10px] font-black text-slate-500 uppercase tracking-widest">
                        <span>Silent "Ghost" Hours</span>
                        <span className="text-blue-400">21:00 - 08:00</span>
                     </div>
                     <div className="h-12 flex gap-1 items-end">
                        {Array.from({ length: 24 }).map((_, i) => (
                          <div 
                            key={i} 
                            className={`flex-1 rounded-t-sm transition-all shadow-inner ${i >= 9 && i <= 17 ? 'bg-blue-500 h-full opacity-60' : 'bg-slate-800 h-1/4 opacity-30'}`}
                          ></div>
                        ))}
                     </div>
                  </div>
                </div>
              )}
            </div>

            <button className="w-full py-5 bg-blue-600 hover:bg-blue-500 text-white rounded-[1.5rem] text-[11px] font-black uppercase tracking-[0.25em] flex items-center justify-center gap-3 shadow-2xl shadow-blue-900/40 transition-all active:scale-[0.98]">
              <Unplug size={18} /> Apply Signal Profile
            </button>
          </section>
        </div>

        {/* Spectral Analyzer Visualizer */}
        <div className="lg:col-span-8 flex flex-col gap-6 overflow-hidden">
          <section className="bg-[#010309] border border-white/5 rounded-[3.5rem] p-12 flex flex-col relative overflow-hidden flex-1 shadow-2xl">
            <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 1px 1px, #fff 1px, transparent 0)', backgroundSize: '32px 32px' }}></div>
            
            <div className="flex justify-between items-start mb-12 z-10">
              <div>
                <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                  <Activity size={24} className="text-blue-500" /> Strategic Spectral Response
                </h3>
                <p className="text-[10px] text-slate-500 mt-2 uppercase font-black tracking-[0.2em]">{activeProfile} Baseline vs. Active Protocol Vector</p>
              </div>
              <div className="flex gap-4">
                <div className="flex items-center gap-3 px-5 py-2.5 bg-blue-500/10 border border-blue-500/20 rounded-xl text-[10px] font-black uppercase text-blue-400 shadow-xl">
                  <div className="w-2 h-2 rounded-full bg-blue-500 shadow-[0_0_10px_#3b82f6] animate-pulse"></div>
                  Ideal Baseline
                </div>
                <div className="flex items-center gap-3 px-5 py-2.5 bg-red-500/10 border border-red-500/20 rounded-xl text-[10px] font-black uppercase text-red-400 shadow-xl">
                  <div className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_10px_#ef4444] animate-pulse"></div>
                  Real-time Signal
                </div>
              </div>
            </div>

            <div className="flex-1 flex gap-1 items-end relative overflow-hidden group/analyzer pb-10">
              {Array.from({ length: 80 }).map((_, i) => {
                const heightBase = Math.abs(Math.sin((i / 80) * Math.PI * 2)) * 60;
                const randomNoise = Math.random() * 20;
                return (
                  <div key={i} className="flex-1 flex flex-col justify-end gap-1 h-full opacity-40 group-hover/analyzer:opacity-100 transition-opacity">
                    <div 
                      className="w-full bg-blue-500/20 border-t border-blue-500/40 rounded-t-sm transition-all duration-1000" 
                      style={{ height: `${heightBase + randomNoise}%` }}
                    ></div>
                    <div 
                      className="w-full bg-red-500/30 border-t border-red-500/60 rounded-t-sm transition-all duration-300" 
                      style={{ height: `${Math.random() * 30}%` }}
                    ></div>
                  </div>
                );
              })}
              
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-[#0b1120]/90 backdrop-blur-2xl border border-white/10 p-10 rounded-[3rem] flex flex-col items-center gap-6 z-20 shadow-2xl scale-110">
                <div className="relative w-40 h-40 flex items-center justify-center">
                  <svg className="w-full h-full transform -rotate-90">
                    <circle cx="80" cy="80" r="74" stroke="currentColor" strokeWidth="4" fill="transparent" className="text-slate-800" />
                    <circle cx="80" cy="80" r="74" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-blue-500" strokeDasharray="465" strokeDashoffset={465 * (1 - entropy/100)} strokeLinecap="round" />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-black text-white">{entropy.toFixed(1)}%</span>
                    <span className="text-[9px] font-black uppercase text-slate-500 tracking-[0.2em] mt-1">Signal Variance</span>
                  </div>
                </div>
                <div className="text-center space-y-1">
                   <p className="text-[11px] font-black text-emerald-400 uppercase tracking-[0.2em]">Fingerprint Verified</p>
                   <p className="text-[9px] text-slate-500 uppercase font-black tracking-widest">Heuristic Detection Confidence: 0.0012%</p>
                </div>
              </div>
            </div>

            <div className="grid grid-cols-4 gap-6 z-10">
              {[
                { label: 'Jitter Accuracy', val: '0.18ms', icon: <Clock size={12} />, color: 'blue' },
                { label: 'MTU Alignment', val: 'Match', icon: <Layers size={12} />, color: 'emerald' },
                { label: 'TLS Integrity', val: 'Verified', icon: <Lock size={12} />, color: 'purple' },
                { label: 'Entropy State', val: 'Nominal', icon: <Activity size={12} />, color: 'emerald' }
              ].map(stat => (
                <div key={stat.label} className="p-5 bg-white/[0.03] border border-white/5 rounded-[1.5rem] flex flex-col gap-3 group/stat hover:border-white/20 transition-all">
                   <div className={`flex items-center gap-3 text-[9px] font-black uppercase tracking-widest text-slate-600 group-hover/stat:text-${stat.color}-400 transition-colors`}>
                      {stat.icon} {stat.label}
                   </div>
                   <div className="text-sm font-black text-slate-200 uppercase tracking-tighter">{stat.val}</div>
                </div>
              ))}
            </div>
          </section>

          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 flex items-center justify-between shadow-2xl">
             <div className="flex items-center gap-6">
                <div className="p-4 rounded-2xl bg-blue-500/10 text-blue-400 border border-blue-500/20 shadow-xl">
                  <Settings2 size={24} />
                </div>
                <div>
                   <h4 className="text-sm font-black text-white uppercase tracking-widest">Advanced Signal Engine Control</h4>
                   <p className="text-[10px] text-slate-500 uppercase font-black tracking-[0.2em] mt-1 italic">Industrial memory-resident transport management</p>
                </div>
             </div>
             <div className="flex gap-4">
                <button className="px-6 py-3 bg-slate-800 text-slate-300 rounded-xl text-[10px] font-black uppercase tracking-widest hover:bg-slate-700 transition-all shadow-inner">Export Profile</button>
                <button className="px-6 py-3 bg-blue-600 text-white rounded-xl text-[10px] font-black uppercase tracking-widest shadow-xl shadow-blue-900/40 hover:bg-blue-500 transition-all active:scale-95">Commit Rules</button>
             </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default SpectrumStudio;
