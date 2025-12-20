
import React, { useState } from 'react';
import { Settings, Globe, Hash, Clock, Wifi, Save, Play, ShieldCheck, Info } from 'lucide-react';
import { C2Profile } from '../types';

const ProfileEditor: React.FC = () => {
  const [profile, setProfile] = useState<C2Profile>({
    id: 'p1',
    name: 'Ghost-HTTP-Stealth',
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    uriPatterns: ['/api/v1/telemetry', '/updates/check', '/static/css/theme.css'],
    headers: { 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/octet-stream' },
    jitter: 25,
    sleep: 5,
    allocator: 'VirtualAlloc'
  });

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-500">
      <header>
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <Globe size={20} /> Malleable C2 Infrastructure
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">Traffic Shaping & EDR Simulation Studio</p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 overflow-hidden">
        <div className="lg:col-span-7 flex flex-col gap-6 overflow-y-auto pr-2 scrollbar-hide">
          <section className="bg-slate-900/40 p-8 rounded-[2.5rem] border border-slate-800 space-y-8">
            <div className="space-y-4">
              <div className="flex items-center gap-3 text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">
                <Settings size={14} className="text-blue-500" /> Protocol Branding
              </div>
              <div className="grid grid-cols-1 gap-4">
                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-600 uppercase">Profile Alias</label>
                  <input value={profile.name} onChange={e => setProfile({...profile, name: e.target.value})} className="w-full bg-black/40 border border-slate-800 rounded-2xl p-4 text-xs font-mono text-emerald-400 outline-none focus:border-emerald-500 transition-all shadow-inner" />
                </div>
                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-600 uppercase">User-Agent String</label>
                  <input value={profile.userAgent} onChange={e => setProfile({...profile, userAgent: e.target.value})} className="w-full bg-black/40 border border-slate-800 rounded-2xl p-4 text-xs font-mono text-slate-400 outline-none focus:border-blue-500 transition-all" />
                </div>
              </div>
            </div>

            <div className="h-px bg-white/5"></div>

            <div className="grid grid-cols-2 gap-8">
              <div className="space-y-4">
                <div className="flex items-center gap-3 text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">
                   <Clock size={14} className="text-yellow-500" /> Timing Profile
                </div>
                <div className="space-y-4">
                   <div className="space-y-2">
                      <div className="flex justify-between text-[10px] font-black text-slate-500 uppercase">
                         <span>Base Sleep</span>
                         <span className="text-emerald-400">{profile.sleep}s</span>
                      </div>
                      <input type="range" min="1" max="300" value={profile.sleep} onChange={e => setProfile({...profile, sleep: parseInt(e.target.value)})} className="w-full accent-emerald-500 opacity-60" />
                   </div>
                   <div className="space-y-2">
                      <div className="flex justify-between text-[10px] font-black text-slate-500 uppercase">
                         <span>Jitter Factor</span>
                         <span className="text-blue-400">{profile.jitter}%</span>
                      </div>
                      <input type="range" min="0" max="100" value={profile.jitter} onChange={e => setProfile({...profile, jitter: parseInt(e.target.value)})} className="w-full accent-blue-500 opacity-60" />
                   </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center gap-3 text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">
                   <Hash size={14} className="text-purple-500" /> URI Logic
                </div>
                <div className="space-y-2">
                  {profile.uriPatterns.map((uri, i) => (
                    <div key={i} className="flex gap-2">
                      <input value={uri} readOnly className="flex-1 bg-black/40 border border-slate-800 rounded-xl p-3 text-[10px] font-mono text-slate-500" />
                    </div>
                  ))}
                  <button className="w-full py-2 bg-slate-800 rounded-xl text-[9px] font-black uppercase text-slate-500 hover:text-white transition-all">+ Add Pattern</button>
                </div>
              </div>
            </div>

            <button className="w-full py-5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-[1.5rem] text-[10px] font-black uppercase tracking-widest flex items-center justify-center gap-3 shadow-2xl shadow-emerald-900/40 transition-all active:scale-[0.98]">
              <Save size={18} /> Synchronize Global Profile
            </button>
          </section>
        </div>

        <div className="lg:col-span-5 flex flex-col gap-6">
          <section className="bg-blue-500/5 border border-blue-500/20 rounded-[2rem] p-6 space-y-4">
             <div className="flex items-center gap-3 text-blue-400">
                <ShieldCheck size={20} />
                <h3 className="text-xs font-black uppercase tracking-widest">OpSec Intelligence</h3>
             </div>
             <p className="text-[10px] text-blue-400/70 italic leading-relaxed">
               "This profile emulates standard Chrome 119 traffic. The use of VirtualAlloc with RWX permissions may trigger memory scanners like Elastic or CrowdStrike. Consider switching to HeapAlloc for higher evasion."
             </p>
          </section>

          <section className="bg-black/40 border border-white/5 rounded-[2rem] p-8 flex-1 flex flex-col">
             <div className="flex justify-between items-center mb-6">
                <h3 className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                   <Play size={14} /> Protocol Simulation
                </h3>
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]"></div>
             </div>
             <div className="flex-1 bg-black p-6 rounded-2xl font-mono text-[10px] text-slate-500 overflow-y-auto space-y-4 border border-white/5">
                <div className="text-emerald-500/70">>>> [BEACON SIGNAL SIMULATION]</div>
                <div className="text-slate-700">GET {profile.uriPatterns[0]} HTTP/1.1</div>
                <div className="text-slate-700">Host: spectre.htb</div>
                <div className="text-slate-700">User-Agent: {profile.userAgent.substring(0, 40)}...</div>
                {Object.entries(profile.headers).map(([k, v]) => (
                  /* Fix: Explicitly cast header value v to string to resolve ReactNode rendering error */
                  <div key={k} className="text-slate-700">{k}: {v as string}</div>
                ))}
                <div className="mt-8 text-blue-500/50">>>> RESPONSE: 200 OK (384 bytes tasking blob)</div>
             </div>
             <div className="mt-6 flex items-start gap-3">
                <Info size={14} className="text-slate-700 shrink-0 mt-0.5" />
                <p className="text-[8px] text-slate-700 uppercase font-black tracking-widest leading-loose">
                  Simulated traffic represents the 'Get Tasking' cycle. POST requests will be used for large data exfiltration.
                </p>
             </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default ProfileEditor;
