
import React, { useState, useEffect, useRef } from 'react';
import { ORBITAL_ASSETS, RF_REGISTRY } from '../constants';
import { OrbitalAsset, CCSDSPacket, SatelliteSubsystem, AOSWindow, OrbitalRelayHop } from '../types';
import { 
  Globe, 
  Target, 
  Activity, 
  Radio, 
  Zap, 
  ShieldAlert, 
  Cpu, 
  Satellite, 
  Signal, 
  Terminal, 
  Users, 
  Compass,
  ArrowUpRight,
  RefreshCcw,
  Search,
  AlertCircle,
  Clock,
  Maximize2,
  Scan,
  Database,
  Crosshair,
  Lock,
  Layers,
  Map as MapIcon,
  Video,
  Unplug,
  Waves,
  Eye,
  Thermometer,
  Battery,
  ShieldCheck,
  Hexagon,
  Shuffle,
  Binary,
  Calendar,
  Send,
  Workflow,
  Plus,
  Network,
  ZapOff,
  Flame,
  TowerControl
} from 'lucide-react';

const SatelliteOrchestrator: React.FC = () => {
  const [selectedSatId, setSelectedSatId] = useState<string | null>(ORBITAL_ASSETS[0].id);
  const [activeTab, setActiveTab] = useState<'tracking' | 'ccsds' | 'subsystems' | 'spectral' | 'aos' | 'relay'>('tracking');
  const [rotation, setRotation] = useState(0);
  const [isInjecting, setIsInjecting] = useState(false);
  const [fuzzingProgress, setFuzzingProgress] = useState(0);
  const [spoofedSubsystems, setSpoofedSubsystems] = useState<Set<string>>(new Set());
  const [liveAsset, setLiveAsset] = useState<OrbitalAsset | null>(null);
  const waterfallRef = useRef<HTMLCanvasElement>(null);
  const socketRef = useRef<WebSocket | null>(null);
  
  const activeSat = liveAsset || ORBITAL_ASSETS.find(s => s.id === selectedSatId) || ORBITAL_ASSETS[0];

  // Tactical Bridge WebSocket Connection for Orbital Data
  useEffect(() => {
    if (!selectedSatId) return;
    const noradId = ORBITAL_ASSETS.find(s => s.id === selectedSatId)?.noradId || 43105;
    
    // Connect to your Python bridge
    const ws = new WebSocket(`ws://localhost:8000/ws/orbital/${noradId}`);
    socketRef.current = ws;

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (!data.error) {
        setLiveAsset(data as OrbitalAsset);
      }
    };

    ws.onclose = () => console.log("Orbital WebSocket connection closed.");
    ws.onerror = () => console.error("Orbital WebSocket error.");

    return () => {
      ws.close();
    };
  }, [selectedSatId]);

  // Relay Chain Mock
  const relayChain: OrbitalRelayHop[] = [
    { id: 'h1', assetId: 'STERN-WATCH-4', latency: 45, snr: 32, uplinkFreq: '8.4GHz', downlinkFreq: '2.2GHz' },
    { id: 'h2', assetId: 'Iridium-Next-142', latency: 120, snr: 68, uplinkFreq: '1.6GHz', downlinkFreq: '1.6GHz' }
  ];

  // Waterfall simulation (Only if not in spectral tab or no bridge)
  useEffect(() => {
    if (activeTab !== 'spectral' || !waterfallRef.current) return;
    const canvas = waterfallRef.current;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId: number;
    const render = () => {
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      ctx.putImageData(imgData, 0, 1);
      
      for (let x = 0; x < canvas.width; x++) {
        const signal = Math.sin(x / 40 + Date.now() / 200) * 40 + 60;
        const noise = Math.random() * 20;
        const intensity = signal + noise;
        ctx.fillStyle = intensity > 85 ? '#3b82f6' : (intensity > 65 ? '#1d4ed8' : '#020617');
        ctx.fillRect(x, 0, 1, 1);
      }
      animationId = requestAnimationFrame(render);
    };
    render();
    return () => cancelAnimationFrame(animationId);
  }, [activeTab]);

  useEffect(() => {
    const interval = setInterval(() => setRotation(prev => (prev + 0.1) % 360), 50);
    return () => clearInterval(interval);
  }, []);

  const handleCcsdsInjection = async () => {
    setIsInjecting(true);
    // Real API Call to your bridge
    try {
      const response = await fetch('http://localhost:8000/api/v1/forge/ccsds', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': 'Bearer valid_token'
        },
        body: JSON.stringify({
          apid: 0x3E5,
          version: 0,
          hex_payload: "08A10000FFFFDEADBEEF00123456789ABCDEF0",
          transmit: true
        })
      });
      const result = await response.json();
      console.log("Forge Result:", result);
    } catch (e) {
      console.error("Uplink failed:", e);
    }
    setTimeout(() => setIsInjecting(false), 3000);
  };

  const startFuzzer = () => {
    setFuzzingProgress(1);
    const interval = setInterval(() => {
      setFuzzingProgress(p => {
        if (p >= 100) { clearInterval(interval); return 0; }
        return p + 2;
      });
    }, 100);
  };

  const toggleSpoofing = (id: string) => {
    setSpoofedSubsystems(prev => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
    });
  };

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-1000">
      <header className="flex justify-between items-start">
        <div className="flex flex-col gap-1">
          <h2 className="text-2xl font-black text-purple-400 uppercase tracking-tighter flex items-center gap-3">
            <Satellite size={24} /> Orbital Engagement Nexus
          </h2>
          <p className="text-[10px] text-slate-500 uppercase tracking-[0.25em] font-black mt-1">Sovereign-Grade SIGINT & Orbital Engagement v4.5.1</p>
        </div>
        
        <div className="flex bg-black/40 p-1.5 rounded-2xl border border-white/5 shadow-2xl overflow-x-auto scrollbar-hide max-w-2xl">
           {[
             { id: 'tracking', icon: <Globe size={12} />, label: 'Orbit' },
             { id: 'ccsds', icon: <Hexagon size={12} />, label: 'Forge' },
             { id: 'subsystems', icon: <Cpu size={12} />, label: 'Subsys' },
             { id: 'relay', icon: <Network size={12} />, label: 'Relay' },
             { id: 'spectral', icon: <Waves size={12} />, label: 'Spectrum' },
             { id: 'aos', icon: <Calendar size={12} />, label: 'AOS' }
           ].map(tab => (
             <button 
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-4 py-2 rounded-xl text-[9px] font-black uppercase transition-all flex items-center gap-2 flex-shrink-0 ${activeTab === tab.id ? 'bg-purple-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
             >
               {tab.icon} {tab.label}
             </button>
           ))}
        </div>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 overflow-hidden">
        {/* Asset Registry Sidebar */}
        <div className="lg:col-span-3 flex flex-col gap-6 overflow-hidden">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-6 flex flex-col gap-6 shadow-2xl overflow-hidden">
             <div className="relative">
                <Search size={14} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" />
                <input 
                  placeholder="NORAD / ASSET ID..." 
                  className="w-full bg-black/40 border border-slate-800 rounded-2xl py-3 pl-11 pr-4 text-[10px] font-black uppercase tracking-widest text-slate-400 outline-none focus:border-purple-500 transition-all"
                />
             </div>

             <div className="flex-1 overflow-y-auto space-y-2 pr-2 scrollbar-hide">
                {ORBITAL_ASSETS.map(sat => (
                  <button
                    key={sat.id}
                    onClick={() => setSelectedSatId(sat.id)}
                    className={`w-full p-4 rounded-[2rem] border transition-all text-left flex flex-col gap-2 relative overflow-hidden group
                      ${selectedSatId === sat.id ? 'bg-purple-500/10 border-purple-500/40 shadow-xl' : 'bg-black/20 border-slate-800/40 hover:border-slate-700'}`}
                  >
                    <div className="flex justify-between items-center">
                      <span className="text-[8px] font-black text-purple-400 uppercase tracking-widest">{sat.type}</span>
                      <span className="text-[8px] font-mono text-slate-700">NORAD: {sat.noradId}</span>
                    </div>
                    <h4 className="text-xs font-black text-slate-100 uppercase tracking-tight flex items-center gap-2 group-hover:text-purple-400 transition-colors">
                      <Satellite size={14} /> {sat.designation}
                    </h4>
                    <div className="flex items-center justify-between mt-1">
                       <div className="flex items-center gap-2">
                          <Signal size={10} className={sat.snr > 30 ? 'text-emerald-500' : 'text-red-500'} />
                          <span className="text-[8px] font-black text-slate-500 uppercase">{sat.snr}dB SNR</span>
                       </div>
                    </div>
                  </button>
                ))}
             </div>

             <div className="p-4 bg-emerald-500/5 rounded-2xl border border-emerald-500/10">
                <h4 className="text-[9px] font-black text-slate-400 uppercase tracking-widest mb-3 flex items-center gap-2">
                   <ShieldCheck size={12} className="text-emerald-500" /> Comm Integrity
                </h4>
                <div className="space-y-2">
                   <div className="flex justify-between items-center p-2 bg-black/40 rounded-lg">
                      <span className="text-[8px] font-black text-emerald-400">UPLINK_SEC</span>
                      <span className="text-[8px] font-mono text-slate-500">AES-256-CCM</span>
                   </div>
                   <div className="flex justify-between items-center p-2 bg-black/40 rounded-lg">
                      <span className="text-[8px] font-black text-emerald-400">LAST_POLL</span>
                      <span className="text-[8px] font-mono text-slate-500">1.2ms AGO</span>
                   </div>
                </div>
             </div>
          </section>
        </div>

        {/* Main Interface Content */}
        <div className="lg:col-span-9 flex flex-col gap-6 overflow-hidden">
          
          {/* TRACKING VIEW */}
          {activeTab === 'tracking' && (
            <div className="flex-1 bg-[#010309] border border-white/5 rounded-[3.5rem] p-10 flex flex-col relative overflow-hidden shadow-2xl">
              <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 1px 1px, #fff 1px, transparent 0)', backgroundSize: '32px 32px' }}></div>
              <div className="flex justify-between items-start mb-8 z-10">
                <div className="flex flex-col gap-2">
                  <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                    <Globe size={24} className="text-purple-500" /> Asset Dynamics & TLE
                  </h3>
                  <div className="p-4 bg-black/60 border border-white/5 rounded-2xl font-mono text-[9px] text-slate-500 leading-tight">
                    {activeSat.tle.line1}<br/>{activeSat.tle.line2}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                   <div className="bg-purple-500/10 border border-purple-500/20 px-6 py-4 rounded-3xl flex flex-col items-end">
                      <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Ground Velocity</span>
                      <span className="text-lg font-black text-white">{activeSat.coords.velocity.toFixed(2)} km/s</span>
                   </div>
                   <div className="bg-purple-500/10 border border-purple-500/20 px-6 py-4 rounded-3xl flex flex-col items-end">
                      <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Alt. Locked</span>
                      <span className="text-lg font-black text-white">{activeSat.altitude.toFixed(0)} km</span>
                   </div>
                </div>
              </div>

              <div className="flex-1 flex items-center justify-center relative">
                 <div className="w-[450px] h-[450px] relative transition-all duration-1000 transform" style={{ perspective: '1000px' }}>
                    <svg viewBox="0 0 100 100" className="w-full h-full animate-[spin_240s_linear_infinite]">
                       <circle cx="50" cy="50" r="48" fill="transparent" stroke="rgba(168, 85, 247, 0.1)" strokeWidth="0.5" />
                       {Array.from({ length: 12 }).map((_, i) => (
                         <ellipse key={i} cx="50" cy="50" rx="48" ry={48 * Math.cos((i * 15 * Math.PI) / 180)} fill="none" stroke="rgba(168, 85, 247, 0.05)" strokeWidth="0.2" />
                       ))}
                       <path d="M30,40 Q40,30 50,45 T70,40 T60,60 T40,55 Z" fill="rgba(168, 85, 247, 0.02)" stroke="rgba(168, 85, 247, 0.1)" strokeWidth="0.5" />
                    </svg>
                    <div className="absolute top-1/2 left-1/2 w-8 h-8 -translate-x-1/2 -translate-y-1/2 z-50 transition-all duration-1000"
                         style={{ transform: `translate(-50%, -50%) rotate(${rotation}deg) translateY(-210px) rotate(-${rotation}deg)` }}>
                      <div className="relative">
                        <div className="absolute inset-0 bg-purple-500 rounded-full blur-md opacity-50 animate-pulse"></div>
                        <Satellite size={32} className="text-purple-400 drop-shadow-[0_0_8px_rgba(168,85,247,0.8)]" />
                      </div>
                    </div>
                 </div>
              </div>
            </div>
          )}

          {/* FORGE VIEW */}
          {activeTab === 'ccsds' && (
            <div className="flex-1 bg-slate-900/40 border border-slate-800 rounded-[3rem] p-10 flex flex-col gap-8 shadow-2xl relative overflow-hidden">
               <div className="flex justify-between items-center z-10">
                <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                  <Hexagon size={24} className="text-blue-500" /> CCSDS Forge & Protocol Fuzzer
                </h3>
                <div className="flex gap-4">
                   <button 
                    onClick={startFuzzer}
                    className={`px-6 py-2 rounded-xl text-[10px] font-black uppercase flex items-center gap-2 transition-all ${fuzzingProgress > 0 ? 'bg-red-600 text-white' : 'bg-slate-800 text-slate-500 hover:text-white'}`}
                   >
                      <Shuffle size={14} className={fuzzingProgress > 0 ? 'animate-spin' : ''} /> 
                      {fuzzingProgress > 0 ? `Fuzzing ${fuzzingProgress}%` : 'Execute Fuzz Loop'}
                   </button>
                   <button 
                    onClick={handleCcsdsInjection}
                    disabled={isInjecting}
                    className="px-8 py-3 bg-blue-600 text-white rounded-xl text-[10px] font-black uppercase shadow-lg shadow-blue-900/40 flex items-center gap-3 transition-all active:scale-95"
                   >
                     {isInjecting ? <Activity size={16} className="animate-spin" /> : <Send size={16} />}
                     {isInjecting ? 'Uplink In Progress...' : 'Inject Space Packet'}
                   </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-8 flex-1 overflow-hidden z-10">
                <div className="flex flex-col gap-6">
                   <div className="p-8 bg-black/60 border border-white/5 rounded-[2.5rem] space-y-6">
                      <div className="grid grid-cols-3 gap-6">
                         <div className="space-y-2">
                            <label className="text-[8px] font-black text-slate-600 uppercase">Version</label>
                            <input defaultValue="000" className="w-full bg-slate-900 border border-white/5 rounded-xl p-3 text-xs font-mono text-blue-400 outline-none" />
                         </div>
                         <div className="space-y-2">
                            <label className="text-[8px] font-black text-slate-600 uppercase">APID Mapping</label>
                            <input defaultValue="0x3E5" className="w-full bg-slate-900 border border-white/5 rounded-xl p-3 text-xs font-mono text-blue-400 outline-none" />
                         </div>
                         <div className="space-y-2">
                            <label className="text-[8px] font-black text-slate-600 uppercase">Sequence</label>
                            <input defaultValue="4012" className="w-full bg-slate-900 border border-white/5 rounded-xl p-3 text-xs font-mono text-blue-400 outline-none" />
                         </div>
                      </div>
                      <div className="space-y-3">
                         <label className="text-[8px] font-black text-slate-600 uppercase">Raw Packet Payload (Hex)</label>
                         <textarea 
                          className="w-full h-40 bg-slate-900 border border-white/5 rounded-2xl p-6 text-[11px] font-mono text-emerald-500/80 resize-none outline-none" 
                          defaultValue="08 A1 00 00 FF FF DE AD BE EF 00 12 34 56 78 9A BC DE F0" 
                         />
                      </div>
                   </div>
                </div>

                <div className="bg-black/60 border border-white/5 rounded-[2.5rem] p-8 flex flex-col gap-6 overflow-hidden">
                   <div className="flex justify-between items-center">
                      <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Baseband Frame Analysis</h4>
                      <span className="text-[8px] font-mono text-blue-500/50">BITS_SYNCHRONIZED</span>
                   </div>
                   <div className="flex-1 font-mono text-[13px] text-slate-600 leading-relaxed overflow-y-auto pr-2 scrollbar-hide grid grid-cols-8 gap-y-2">
                      {Array.from({ length: 64 }).map((_, i) => (
                        <span key={i} className={`hover:text-blue-400 cursor-default transition-colors ${i < 6 ? 'text-blue-500 font-bold' : (i > 60 ? 'text-red-500 font-bold' : '')}`}>
                          {(Math.random() * 255).toString(16).toUpperCase().padStart(2, '0')}
                        </span>
                      ))}
                   </div>
                   <div className="mt-auto p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-2xl flex items-center justify-between">
                      <span className="text-[9px] font-black text-emerald-500 uppercase">CRC-16 Integrity</span>
                      <span className="text-xs font-mono text-white">0xFEA2 (VALID)</span>
                   </div>
                </div>
              </div>
            </div>
          )}

          {/* SUBSYSTEMS VIEW */}
          {activeTab === 'subsystems' && (
            <div className="flex-1 grid grid-cols-2 lg:grid-cols-3 gap-6 overflow-y-auto pr-2 scrollbar-hide pb-20">
               {activeSat.subsystems.map(sub => {
                 const isSpoofed = spoofedSubsystems.has(sub.id);
                 return (
                 <div key={sub.id} className="bg-slate-900/40 border border-slate-800 p-8 rounded-[2.5rem] flex flex-col gap-6 group hover:border-purple-500/40 transition-all relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
                       <Cpu size={80} />
                    </div>
                    <div className="flex justify-between items-start z-10">
                       <div className={`p-4 rounded-3xl ${sub.status === 'nominal' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                          {sub.id === 'eps' ? <Battery size={24} /> : (sub.id === 'aocs' ? <Compass size={24} /> : (sub.id === 'thermal' ? <Thermometer size={24} /> : <Signal size={24} />))}
                       </div>
                       <div className="flex flex-col items-end gap-2">
                         {isSpoofed && <span className="text-[7px] bg-purple-600 text-white px-2 py-0.5 rounded-full font-black animate-pulse uppercase">Spoof Active</span>}
                         <span className={`text-[8px] font-black px-2 py-0.5 rounded-full border ${sub.status === 'nominal' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 'bg-red-500/10 text-red-400 border-red-500/20'}`}>
                            {sub.status.toUpperCase()}
                         </span>
                       </div>
                    </div>
                    <div className="z-10">
                       <h4 className="text-sm font-black text-white uppercase tracking-tight">{sub.name}</h4>
                       <div className="w-full h-1 bg-slate-800 rounded-full mt-3 overflow-hidden">
                          <div className={`h-full transition-all duration-1000 ${sub.load > 80 ? 'bg-red-500' : 'bg-blue-500'}`} style={{ width: `${sub.load * 100}%` }}></div>
                       </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4 z-10">
                       {Object.entries(sub.telemetry).map(([k, v]) => (
                         <div key={k} className="flex flex-col">
                            <span className="text-[8px] font-black text-slate-600 uppercase tracking-widest">{k.replace('_', ' ')}</span>
                            <span className={`text-[10px] font-mono truncate ${isSpoofed ? 'text-purple-400' : 'text-slate-300'}`}>{v}</span>
                         </div>
                       ))}
                    </div>
                    <div className="mt-auto flex gap-2 z-10">
                       <button className="flex-1 py-4 bg-black/60 border border-white/5 text-slate-500 rounded-2xl text-[9px] font-black uppercase hover:bg-purple-600 hover:text-white transition-all shadow-lg">Target</button>
                       <button 
                        onClick={() => toggleSpoofing(sub.id)}
                        className={`px-4 py-4 rounded-2xl text-[9px] font-black uppercase transition-all shadow-lg ${isSpoofed ? 'bg-purple-600 text-white' : 'bg-black/60 border border-white/5 text-slate-500 hover:text-purple-400'}`}
                       >
                         <ZapOff size={14} />
                       </button>
                    </div>
                 </div>
               )})}
            </div>
          )}

          {/* RELAY VIEW */}
          {activeTab === 'relay' && (
            <div className="flex-1 bg-slate-900/40 border border-slate-800 rounded-[3rem] p-10 flex flex-col gap-10 shadow-2xl relative">
               {/* ... Keep existing relay layout ... */}
            </div>
          )}

          {/* SPECTRAL VIEW */}
          {activeTab === 'spectral' && (
             <div className="flex-1 bg-black rounded-[3.5rem] border border-white/5 p-12 flex flex-col gap-10 shadow-2xl overflow-hidden relative">
               {/* ... Keep existing spectral layout ... */}
             </div>
          )}

          {/* AOS PLANNER VIEW */}
          {activeTab === 'aos' && (
            <div className="flex-1 bg-slate-900/40 border border-slate-800 rounded-[3rem] p-10 flex flex-col gap-10 shadow-2xl relative">
               {/* ... Keep existing AOS layout ... */}
            </div>
          )}

        </div>
      </div>
    </div>
  );
};

export default SatelliteOrchestrator;
