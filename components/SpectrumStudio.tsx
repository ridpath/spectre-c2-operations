
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
  Unplug,
  Flame,
  HardDrive,
  Dna,
  Binary
} from 'lucide-react';

type ProfileType = 'Office365' | 'AWS' | 'GitHub' | 'Slack' | 'GoogleWorkspace' | 'Zoom' | 'PhantomVector';

const SpectrumStudio: React.FC = () => {
  const [activeProfile, setActiveProfile] = useState<ProfileType>('Office365');
  const [isLive, setIsLive] = useState(true);
  const [jitterFactor, setJitterFactor] = useState(45);
  const [entropy, setEntropy] = useState(12);
  const [activeTab, setActiveTab] = useState<'shaping' | 'obfuscation' | 'recording'>('shaping');
  const [isRecordingIQ, setIsRecordingIQ] = useState(false);
  const [isObfuscating, setIsObfuscating] = useState(false);
  const [spectrumData, setSpectrumData] = useState<number[]>([]);
  const [streamingMode, setStreamingMode] = useState<'Standard' | 'VITA-49'>('Standard');
  const waterfallRef = useRef<HTMLCanvasElement>(null);
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!isLive) return;
    const ws = new WebSocket(`ws://localhost:8000/ws/spectrum`);
    socketRef.current = ws;
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.data) setSpectrumData(data.data);
    };
    return () => ws.close();
  }, [isLive]);

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
        const intensity = (currentData[binIndex] + 120) * 2;
        
        ctx.fillStyle = intensity > 100 ? '#3b82f6' : (intensity > 60 ? '#1d4ed8' : '#020617');
        if (isObfuscating && Math.random() > 0.95) ctx.fillStyle = '#ef4444'; // Chaff simulation
        ctx.fillRect(x, 0, 1, 1);
      }
      animationId = requestAnimationFrame(render);
    };
    render();
    return () => cancelAnimationFrame(animationId);
  }, [spectrumData, isObfuscating]);

  const mimicryDetails: Record<ProfileType, { icon: any, color: string, desc: string, risk: string, protocol: string }> = {
    'Office365': { icon: <Cloud size={32} />, color: 'blue', desc: 'Mimics Outlook/SharePoint web-socket traffic.', risk: 'Low', protocol: 'HTTPS/2' },
    'AWS': { icon: <Layers size={32} />, color: 'orange', desc: 'Mimics S3 API calls and EC2 telemetry.', risk: 'Medium', protocol: 'HTTPS/1.1' },
    'GitHub': { icon: <Github size={32} />, color: 'emerald', desc: 'Mimics Git-over-HTTPS and Action runners.', risk: 'Low', protocol: 'HTTPS/TLS1.3' },
    'Slack': { icon: <MessageSquare size={32} />, color: 'purple', desc: 'Mimics persistent RTM socket connections.', risk: 'Low', protocol: 'WSS (WebSockets)' },
    'GoogleWorkspace': { icon: <Globe size={32} />, color: 'red', desc: 'Mimics gRPC-based Drive synchronization.', risk: 'Low', protocol: 'HTTP/3 (QUIC)' },
    'Zoom': { icon: <Video size={32} />, color: 'blue', desc: 'Masks C2 within WebRTC / UDP media streams.', risk: 'Ultra-Low', protocol: 'UDP/SRTP' },
    'PhantomVector': { icon: <Radio size={32} />, color: 'red', desc: 'Advanced vector-based protocol mimicry.', risk: 'High', protocol: 'VECTORIZED/RAW' }
  };

  return (
    <div className="h-full flex flex-col gap-8 animate-in fade-in duration-700">
      <header className="flex justify-between items-start">
        <div className="flex flex-col gap-1">
          <h2 className="text-2xl font-black text-blue-400 uppercase tracking-tighter flex items-center gap-3">
            <Wifi size={24} /> Spectrum Studio v4.6
          </h2>
          <p className="text-[10px] text-slate-500 uppercase tracking-[0.2em] font-black mt-1">Professional RF Orchestration & Mimicry</p>
        </div>
        
        <div className="flex items-center gap-4 bg-slate-900/60 p-2 rounded-2xl border border-white/5 shadow-2xl">
           <button 
            onClick={() => setStreamingMode(streamingMode === 'Standard' ? 'VITA-49' : 'Standard')}
            className={`px-4 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest transition-all ${streamingMode === 'VITA-49' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-500'}`}
           >
             Mode: {streamingMode}
           </button>
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
                onClick={() => setActiveTab('obfuscation')}
                className={`flex-1 py-2 text-[9px] font-black uppercase rounded-xl transition-all ${activeTab === 'obfuscation' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
              >Chaff</button>
              <button 
                onClick={() => setActiveTab('recording')}
                className={`flex-1 py-2 text-[9px] font-black uppercase rounded-xl transition-all ${activeTab === 'recording' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
              >IQ Vault</button>
            </div>

            <div className="flex-1 space-y-6">
              {activeTab === 'shaping' && (
                <div className="space-y-4 animate-in slide-in-from-left-4 duration-300">
                  <div className="flex justify-between items-center">
                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em]">Burst Jitter</label>
                    <span className="text-xs font-mono text-blue-400">{jitterFactor}%</span>
                  </div>
                  <input 
                    type="range" min="5" max="95" value={jitterFactor} 
                    onChange={e => setJitterFactor(parseInt(e.target.value))}
                    className="w-full h-1 bg-slate-800 rounded-full appearance-none accent-blue-500"
                  />
                </div>
              )}

              {activeTab === 'obfuscation' && (
                <div className="space-y-6 animate-in slide-in-from-left-4 duration-300">
                  <div className="p-4 bg-red-500/5 border border-red-500/20 rounded-2xl">
                    <h5 className="text-[10px] font-black text-red-400 uppercase mb-2 flex items-center gap-2">
                       <Flame size={12} /> Chaff Generation
                    </h5>
                    <p className="text-[9px] text-slate-500 leading-relaxed italic">
                      Injects synthetic spectral noise to mask the true C2 vector footprint.
                    </p>
                  </div>
                  <button 
                    onClick={() => setIsObfuscating(!isObfuscating)}
                    className={`w-full py-4 rounded-2xl text-[10px] font-black uppercase flex items-center justify-center gap-2 transition-all ${isObfuscating ? 'bg-red-600 text-white shadow-red-900/40' : 'bg-slate-800 text-slate-400'}`}
                  >
                    <Zap size={14} /> {isObfuscating ? 'Deactivate Chaff' : 'Ignite Obfuscation'}
                  </button>
                </div>
              )}

              {activeTab === 'recording' && (
                <div className="space-y-6 animate-in slide-in-from-left-4 duration-300">
                  <div className="p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-2xl">
                    <h5 className="text-[10px] font-black text-emerald-400 uppercase mb-2 flex items-center gap-2">
                       <HardDrive size={12} /> High-Speed IQ Vault
                    </h5>
                    <p className="text-[9px] text-slate-500 leading-relaxed italic">
                      Record raw IQ samples from the current center frequency for offline replay analysis.
                    </p>
                  </div>
                  <button 
                    onClick={() => setIsRecordingIQ(!isRecordingIQ)}
                    className={`w-full py-4 rounded-2xl text-[10px] font-black uppercase flex items-center justify-center gap-2 transition-all ${isRecordingIQ ? 'bg-emerald-600 text-white animate-pulse' : 'bg-slate-800 text-slate-400'}`}
                  >
                    <Activity size={14} /> {isRecordingIQ ? 'Recording IQ Stream...' : 'Start IQ Capture'}
                  </button>
                </div>
              )}
            </div>

            <button className="w-full py-5 bg-blue-600 hover:bg-blue-500 text-white rounded-[1.5rem] text-[11px] font-black uppercase tracking-[0.25em] flex items-center justify-center gap-3 shadow-2xl shadow-blue-900/40">
              <Unplug size={18} /> Apply Spectral Profile
            </button>
          </section>
        </div>

        <div className="lg:col-span-8 flex flex-col gap-6 overflow-hidden">
          <section className="bg-[#010309] border border-white/5 rounded-[3.5rem] p-12 flex flex-col relative overflow-hidden flex-1 shadow-2xl">
            <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 1px 1px, #fff 1px, transparent 0)', backgroundSize: '32px 32px' }}></div>
            <div className="flex justify-between items-start mb-12 z-10">
              <div>
                <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                  <Dna size={24} className="text-blue-500" /> Response Distribution
                </h3>
                <p className="text-[10px] text-slate-500 mt-2 uppercase font-black tracking-[0.2em]">{activeProfile} Baseline Map</p>
              </div>
            </div>
            <div className="flex-1 flex gap-1 items-end relative overflow-hidden group/analyzer pb-10">
              <canvas ref={waterfallRef} className="absolute inset-0 w-full h-full opacity-60" width={800} height={400} />
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default SpectrumStudio;
