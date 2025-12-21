
import React, { useState, useEffect, useRef } from 'react';
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
  const [spectrumData, setSpectrumData] = useState<number[]>([]);
  const waterfallRef = useRef<HTMLCanvasElement>(null);
  const socketRef = useRef<WebSocket | null>(null);

  // Tactical Bridge WebSocket Connection for Spectrum Data
  useEffect(() => {
    if (!isLive) return;

    const ws = new WebSocket(`ws://localhost:8000/ws/spectrum`);
    socketRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.data) {
        setSpectrumData(data.data);
      }
    };

    return () => {
      ws.close();
    };
  }, [isLive]);

  // Waterfall simulation using live data
  useEffect(() => {
    if (!waterfallRef.current) return;
    const canvas = waterfallRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId: number;
    const render = () => {
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      ctx.putImageData(imgData, 0, 1);
      
      const currentData = spectrumData.length > 0 ? spectrumData : Array.from({length: 120}, () => -110 + Math.random() * 20);

      for (let x = 0; x < canvas.width; x++) {
        const binIndex = Math.floor((x / canvas.width) * currentData.length);
        const intensity = (currentData[binIndex] + 120) * 2; // Normalize dBm to 0-255 scale roughly
        
        ctx.fillStyle = intensity > 100 ? '#3b82f6' : (intensity > 60 ? '#1d4ed8' : '#020617');
        ctx.fillRect(x, 0, 1, 1);
      }
      animationId = requestAnimationFrame(render);
    };
    render();
    return () => cancelAnimationFrame(animationId);
  }, [spectrumData]);

  const mimicryDetails: Record<ProfileType, { icon: any, color: string, desc: string, risk: string, protocol: string }> = {
    'Office365': { icon: <Cloud size={32} />, color: 'blue', desc: 'Mimics Outlook/SharePoint web-socket traffic.', risk: 'Low', protocol: 'HTTPS/2' },
    'AWS': { icon: <Layers size={32} />, color: 'orange', desc: 'Mimics S3 API calls and EC2 telemetry.', risk: 'Medium', protocol: 'HTTPS/1.1' },
    'GitHub': { icon: <Github size={32} />, color: 'emerald', desc: 'Mimics Git-over-HTTPS and Action runners.', risk: 'Low', protocol: 'HTTPS/TLS1.3' },
    'Slack': { icon: <MessageSquare size={32} />, color: 'purple', desc: 'Mimics persistent RTM socket connections.', risk: 'Low', protocol: 'WSS (WebSockets)' },
    'GoogleWorkspace': { icon: <Globe size={32} />, color: 'red', desc: 'Mimics gRPC-based Drive synchronization.', risk: 'Low', protocol: 'HTTP/3 (QUIC)' },
    'Zoom': { icon: <Video size={32} />, color: 'blue', desc: 'Masks C2 within WebRTC / UDP media streams.', risk: 'Ultra-Low', protocol: 'UDP/SRTP' },
    'PhantomVector': { icon: <Radio size={32} />, color: 'red', desc: 'Industrialized vector-based protocol mimicry.', risk: 'Elite', protocol: 'VECTORIZED/RAW' }
  };

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
             {isLive ? 'Bridge Live' : 'Simulation Mode'}
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
                  </div>
                </div>
              )}
            </div>

            <button className="w-full py-5 bg-blue-600 hover:bg-blue-500 text-white rounded-[1.5rem] text-[11px] font-black uppercase tracking-[0.25em] flex items-center justify-center gap-3 shadow-2xl shadow-blue-900/40 transition-all active:scale-[0.98]">
              <Unplug size={18} /> Apply Signal Profile
            </button>
          </section>
        </div>

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
            </div>

            <div className="flex-1 flex gap-1 items-end relative overflow-hidden group/analyzer pb-10">
              <canvas ref={waterfallRef} className="absolute inset-0 w-full h-full opacity-60" width={800} height={400} />
              
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 bg-[#0b1120]/90 backdrop-blur-2xl border border-white/10 p-10 rounded-[3rem] flex flex-col items-center gap-6 z-20 shadow-2xl scale-110">
                <div className="relative w-40 h-40 flex items-center justify-center">
                   {/* Center gauge logic ... */}
                   <span className="text-3xl font-black text-white">{isLive ? "BRIDGE" : "SIM"}</span>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default SpectrumStudio;
