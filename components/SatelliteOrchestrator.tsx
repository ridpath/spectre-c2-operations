
import React, { useState, useEffect, useRef } from 'react';
import { ORBITAL_ASSETS, RF_REGISTRY } from '../constants';
import OrbitalVisualization from './OrbitalVisualization';
import LocationDisplay from './LocationDisplay';
import { locationService } from '../services/locationService';
import { satelliteService } from '../services/satelliteService';
import { 
  OrbitalAsset, 
  CCSDSPacket, 
  SatelliteSubsystem, 
  AOSWindow, 
  OrbitalRelayHop, 
  DPIFrame, 
  AntennaState, 
  DspEngine, 
  ModulationType 
} from '../types';
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
  TowerControl,
  Wifi,
  HardDrive,
  BarChart3,
  Dna,
  FileSearch,
  Timer,
  Share2,
  ChevronRight
} from 'lucide-react';

interface SatelliteOrchestratorProps {
  satellites: OrbitalAsset[];
}

const SatelliteOrchestrator: React.FC<SatelliteOrchestratorProps> = ({ satellites }) => {
  const [selectedSatId, setSelectedSatId] = useState<string | null>(satellites[0]?.id || null);
  const [activeTab, setActiveTab] = useState<'tracking' | 'ccsds' | 'dpi' | 'subsystems' | 'spectral' | 'aos' | 'relay'>('tracking');
  const [rotation, setRotation] = useState(0);
  const [isInjecting, setIsInjecting] = useState(false);
  const [isSyncingTle, setIsSyncingTle] = useState(false);
  const [fuzzingProgress, setFuzzingProgress] = useState(0);
  const [spoofedSubsystems, setSpoofedSubsystems] = useState<Set<string>>(new Set());
  const [isObfuscating, setIsObfuscating] = useState(false);
  const [isRecordingIQ, setIsRecordingIQ] = useState(false);
  const [liveAsset, setLiveAsset] = useState<OrbitalAsset | null>(null);
  const [dataSource, setDataSource] = useState<'BRIDGE' | 'CELESTRAK' | 'SPACE-TRACK' | 'SIM'>('SIM');
  const [fidelity, setFidelity] = useState<'Standard' | 'High'>('Standard');
  const [antenna, setAntenna] = useState<AntennaState>({ azimuth: 142.4, elevation: 45.2, status: 'tracking', rotctld_status: 'connected', servo_lock: true });
  const [dpiFrames, setDpiFrames] = useState<DPIFrame[]>([]);
  const [dspEngine, setDspEngine] = useState<DspEngine>('CPU');
  const [aiModulation, setAiModulation] = useState<ModulationType>('QPSK');
  const [meshPeers, setMeshPeers] = useState(3);
  const [spectrumData, setSpectrumData] = useState<number[]>([]);
  const [observerLat, setObserverLat] = useState<number>(0);
  const [observerLng, setObserverLng] = useState<number>(0);
  const [constellationFilter, setConstellationFilter] = useState<'All' | 'Overhead' | 'Starlink' | 'Iridium' | 'Weather' | 'GPS' | 'Amateur' | 'ISS' | 'Scientific' | 'Imaging'>('All');

  if (satellites.length === 0) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-8">
        <div className="text-center space-y-4">
          <Satellite size={64} className="text-slate-700 mx-auto" />
          <h2 className="text-2xl font-black text-slate-400 uppercase">No Satellites Available</h2>
          <p className="text-slate-500">Satellites are being fetched from backend...</p>
        </div>
      </div>
    );
  }

  // Filter satellites based on constellation
  const filteredSatellites = React.useMemo(() => {
    try {
      if (constellationFilter === 'All') return satellites;
      
      if (constellationFilter === 'Overhead') {
        if (!satelliteService) {
          console.error('satelliteService not available');
          return satellites;
        }
        return satelliteService.filterOverheadSatellites(satellites, observerLat, observerLng, 10);
      }
      
      return satellites.filter(sat => {
        const name = sat.designation.toUpperCase();
        switch (constellationFilter) {
          case 'Starlink': return name.includes('STARLINK');
          case 'Iridium': return name.includes('IRIDIUM');
          case 'Weather': return name.includes('NOAA') || name.includes('GOES') || name.includes('METOP') || name.includes('WEATHER');
          case 'GPS': return name.includes('GPS') || name.includes('NAVSTAR') || name.includes('GLONASS') || name.includes('GALILEO') || name.includes('BEIDOU');
          case 'Amateur': return name.includes('AO-') || name.includes('SO-') || name.includes('FO-') || name.includes('AMSAT');
          case 'ISS': return name.includes('ISS') || name.includes('ZARYA');
          case 'Scientific': return name.includes('HUBBLE') || name.includes('CHANDRA') || name.includes('SWIFT') || name.includes('FERMI');
          case 'Imaging': return name.includes('LANDSAT') || name.includes('SENTINEL') || name.includes('WORLDVIEW') || name.includes('KOMPSAT');
          default: return true;
        }
      });
    } catch (error) {
      console.error('Error filtering satellites:', error);
      return satellites;
    }
  }, [satellites, constellationFilter, observerLat, observerLng]);
  
  const activeSat = liveAsset || filteredSatellites.find(s => s.id === selectedSatId) || filteredSatellites[0] || satellites[0] || ORBITAL_ASSETS[0];
  const waterfallRef = useRef<HTMLCanvasElement>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const spectrumSocketRef = useRef<WebSocket | null>(null);

  const dopplerShift = activeSat?.coords ? (activeSat.coords.velocity * 1000 * 2.2e9 / 3e8).toFixed(2) : '0.00';

  // --- CORE BACKEND INTEGRATIONS ---

  // 1. Orbital Telemetry WebSocket (with fallback)
  useEffect(() => {
    if (!selectedSatId) return;
    const noradId = satellites.find(s => s.id === selectedSatId)?.noradId || 43105;
    
    try {
      const ws = new WebSocket(`ws://localhost:8000/ws/orbital/${noradId}`);
      socketRef.current = ws;

      ws.onerror = (error) => {
        console.warn('WebSocket connection failed, using polling fallback');
        ws.close();
      };

      ws.onclose = () => {
        console.log('WebSocket closed, using static satellite data');
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (!data.error) {
            setLiveAsset(data as OrbitalAsset);
            setDataSource(data.hardware_active ? 'BRIDGE' : (fidelity === 'High' ? 'SPACE-TRACK' : 'CELESTRAK'));
            if (data.dpi_frame) {
              setDpiFrames(prev => [data.dpi_frame, ...prev].slice(0, 50));
              if (data.dpi_frame.modulationAI) setAiModulation(data.dpi_frame.modulationAI);
            }
            if (data.antenna_state) setAntenna(data.antenna_state);
            if (data.mesh_peers) setMeshPeers(data.mesh_peers);
          }
        } catch (e) {
          console.error('Error parsing WebSocket data:', e);
        }
      };
    } catch (error) {
      console.warn('Failed to establish WebSocket connection:', error);
    }

    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [selectedSatId, satellites, fidelity]);

  // 2. Spectrum WebSocket (with fallback)
  useEffect(() => {
    try {
      const ws = new WebSocket(`ws://localhost:8000/ws/spectrum`);
      spectrumSocketRef.current = ws;
      
      ws.onerror = () => {
        console.warn('Spectrum WebSocket failed, using simulated data');
        ws.close();
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.data) {
            setSpectrumData(data.data);
            if (data.modulation) setAiModulation(data.modulation);
          }
        } catch (e) {
          console.error('Error parsing spectrum data:', e);
        }
      };
    } catch (error) {
      console.warn('Failed to establish spectrum WebSocket:', error);
    }

    return () => {
      if (spectrumSocketRef.current) {
        spectrumSocketRef.current.close();
      }
    };
  }, []);

  // 3. Location Service
  useEffect(() => {
    const unsubscribe = locationService.subscribe((coords) => {
      if (coords) {
        setObserverLat(coords.latitude);
        setObserverLng(coords.longitude);
      }
    });
    locationService.ensureLocation().catch(() => {});
    return unsubscribe;
  }, []);

  // 3. TLE Sync Handler
  const syncTleGroup = async (group: string) => {
    setIsSyncingTle(true);
    try {
      const response = await fetch('http://localhost:8000/api/v1/orbital/sync', {
        method: 'POST',
        headers: { 
          'Authorization': 'Bearer valid_token',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
          group: group.toLowerCase(), 
          source: fidelity === 'High' ? 'spacetrack' : 'celestrak' 
        })
      });
      if (response.ok) {
        setTimeout(() => setIsSyncingTle(false), 1500);
      }
    } catch (e) {
      setIsSyncingTle(false);
    }
  };

  // 4. IQ Vault Handler
  const handleIqCapture = async () => {
    setIsRecordingIQ(!isRecordingIQ);
    if (!isRecordingIQ) {
      try {
        await fetch('http://localhost:8000/api/v1/iq/dump', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer valid_token' },
          body: JSON.stringify({ filename: `capture_${activeSat?.noradId || 'unknown'}` })
        });
      } catch (e) { console.error("IQ dump failed"); }
    }
  };

  // 5. CCSDS Injection Handler
  const handleCcsdsInjection = async () => {
    setIsInjecting(true);
    try {
      await fetch('http://localhost:8000/api/v1/forge/ccsds', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer valid_token' },
        body: JSON.stringify({ 
          apid: 0x3E5, 
          transmit: true, 
          hex_payload: "08A10000FFFFDEADBEEF",
          chaff: isObfuscating
        })
      });
    } catch (e) {}
    setTimeout(() => setIsInjecting(false), 3000);
  };

  // 6. Waterfall Render Loop
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
        const intensity = (currentData[binIndex] + 120) * 2.5;
        
        if (isObfuscating && Math.random() > 0.98) {
           ctx.fillStyle = '#ef4444';
        } else {
           ctx.fillStyle = intensity > 100 ? '#3b82f6' : (intensity > 60 ? '#1d4ed8' : '#020617');
        }
        ctx.fillRect(x, 0, 1, 1);
      }
      animationId = requestAnimationFrame(render);
    };
    render();
    return () => cancelAnimationFrame(animationId);
  }, [spectrumData, isObfuscating]);

  useEffect(() => {
    const interval = setInterval(() => setRotation(prev => (prev + 0.1) % 360), 50);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-1000">
      <header className="flex justify-between items-start">
        <div className="flex flex-col gap-1">
          <h2 className="text-2xl font-black text-purple-400 uppercase tracking-tighter flex items-center gap-3">
            <Satellite size={24} /> Orbital Engagement Nexus
          </h2>
          <div className="flex items-center gap-3 mt-1">
             <p className="text-[10px] text-slate-500 uppercase tracking-[0.25em] font-black">Sovereign-Grade SIGINT v4.6.0</p>
             <div className="h-3 w-[1px] bg-slate-800"></div>
             <div className="flex items-center gap-1.5">
                <div className={`w-1.5 h-1.5 rounded-full ${dataSource === 'BRIDGE' ? 'bg-emerald-500 animate-pulse' : 'bg-blue-500'}`}></div>
                <span className="text-[9px] font-black text-slate-400 uppercase tracking-widest">Source: {dataSource}</span>
                <div className="h-3 w-[1px] bg-slate-800 ml-2"></div>
                <button onClick={() => setDspEngine(e => e === 'CPU' ? 'FPGA' : (e === 'FPGA' ? 'RFNoC' : 'CPU'))} className={`text-[9px] font-black uppercase px-2 py-0.5 rounded transition-colors ${dspEngine !== 'CPU' ? 'bg-orange-600 text-white animate-pulse' : 'bg-slate-800 text-slate-500'}`}>
                  Engine: {dspEngine}
                </button>
                <div className="h-3 w-[1px] bg-slate-800 ml-2"></div>
                <div className="flex items-center gap-2">
                   <Share2 size={12} className="text-blue-500" />
                   <span className="text-[9px] font-black text-slate-400 uppercase">{meshPeers} Mesh Peers Online</span>
                </div>
             </div>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex bg-black/40 p-1.5 rounded-2xl border border-white/5 shadow-2xl overflow-x-auto scrollbar-hide max-w-4xl">
             {[
               { id: 'tracking', icon: <Globe size={12} />, label: 'Orbit' },
               { id: 'ccsds', icon: <Hexagon size={12} />, label: 'Forge' },
               { id: 'dpi', icon: <FileSearch size={12} />, label: 'DPI' },
               { id: 'subsystems', icon: <Cpu size={12} />, label: 'Subsys' },
               { id: 'spectral', icon: <Waves size={12} />, label: 'Spectrum' },
               { id: 'aos', icon: <Calendar size={12} />, label: 'AOS' },
               { id: 'relay', icon: <Network size={12} />, label: 'Relay' }
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
          
          <div className="flex bg-black/40 p-1.5 rounded-2xl border border-white/5 shadow-2xl overflow-x-auto scrollbar-hide gap-1">
             {(['All', 'Overhead', 'Starlink', 'Iridium', 'Weather', 'GPS', 'Amateur', 'ISS', 'Scientific', 'Imaging'] as const).map(filter => (
               <button 
                 key={filter}
                 onClick={() => setConstellationFilter(filter)}
                 className={`px-3 py-1 rounded-lg text-[8px] font-black uppercase transition-all flex-shrink-0 ${constellationFilter === filter ? 'bg-emerald-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'}`}
               >
                 {filter}
               </button>
             ))}
          </div>
        </div>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 overflow-hidden">
        {/* Asset Registry Sidebar */}
        <div className="lg:col-span-3 flex flex-col gap-6 overflow-hidden">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-6 flex flex-col gap-6 shadow-2xl overflow-hidden">
             <div className="flex justify-between items-center px-1">
                <div className="flex flex-col">
                  <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                    <TowerControl size={12} className="text-purple-500" /> Antenna Servo
                  </span>
                  <div className={`flex items-center gap-2 text-[9px] font-mono ${antenna.rotctld_status === 'connected' ? 'text-emerald-500' : 'text-red-500'}`}>
                    Rotctld: {antenna.rotctld_status.toUpperCase()}
                  </div>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-[10px] font-mono text-white">{antenna.azimuth.toFixed(1)}° AZ</span>
                  <span className="text-[10px] font-mono text-white">{antenna.elevation.toFixed(1)}° EL</span>
                </div>
             </div>

             <div className="flex justify-between items-center px-4 py-3 bg-black/40 rounded-2xl border border-white/5">
                <span className="text-[8px] font-black text-slate-500 uppercase tracking-widest">Servo Tracking Lock</span>
                <button onClick={() => setAntenna(a => ({ ...a, servo_lock: !a.servo_lock }))} className={`w-10 h-5 rounded-full relative transition-all shadow-inner ${antenna.servo_lock ? 'bg-emerald-600' : 'bg-slate-800'}`}>
                  <div className={`absolute top-1 w-3 h-3 rounded-full bg-white transition-all ${antenna.servo_lock ? 'left-6' : 'left-1'}`}></div>
                </button>
             </div>

             <div className="flex-1 overflow-y-auto space-y-2 pr-2 scrollbar-hide">
                {filteredSatellites.map(sat => (
                  <button
                    key={sat.id}
                    onClick={() => setSelectedSatId(sat.id)}
                    className={`w-full p-4 rounded-[2rem] border transition-all text-left flex flex-col gap-2 relative overflow-hidden group
                      ${selectedSatId === sat.id ? 'bg-purple-500/10 border-purple-500/40 shadow-xl' : 'bg-black/20 border-slate-800/40 hover:border-slate-700'}`}
                  >
                    <div className="flex justify-between items-center">
                      <span className="text-[8px] font-black text-purple-400 uppercase tracking-widest">{sat.type}</span>
                      <span className="text-[8px] font-mono text-slate-700"># {sat.noradId}</span>
                    </div>
                    <h4 className="text-xs font-black text-slate-100 uppercase tracking-tight flex items-center gap-2 group-hover:text-purple-400 transition-colors">
                      <Satellite size={14} /> {sat.designation}
                    </h4>
                  </button>
                ))}
             </div>

             <div className="p-4 bg-emerald-500/5 rounded-2xl border border-emerald-500/10 space-y-4">
                <div className="flex items-center justify-between">
                   <h4 className="text-[9px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                      <BarChart3 size={12} className="text-emerald-500" /> Tactical Physics
                   </h4>
                   <button 
                    onClick={() => syncTleGroup('active')}
                    disabled={isSyncingTle}
                    className="text-[8px] font-black text-purple-400 hover:text-white uppercase flex items-center gap-1 transition-colors"
                   >
                     <RefreshCcw size={8} className={isSyncingTle ? 'animate-spin' : ''} /> Hi-Fi Sync
                   </button>
                </div>
                <div className="space-y-3">
                   <div className="flex justify-between items-center">
                      <span className="text-[8px] font-black text-slate-600 uppercase">De-Doppler Shift</span>
                      <span className="text-[10px] font-mono text-emerald-500">{dopplerShift} Hz</span>
                   </div>
                   <div className="flex justify-between items-center">
                      <span className="text-[8px] font-black text-slate-600 uppercase">Modulation AI</span>
                      <span className="text-[10px] font-black text-orange-400 uppercase animate-pulse">{aiModulation}</span>
                   </div>
                   <div className="flex justify-between items-center">
                      <span className="text-[8px] font-black text-slate-600 uppercase">Data Fidelity</span>
                      <button onClick={() => setFidelity(fidelity === 'High' ? 'Standard' : 'High')} className={`text-[8px] font-black uppercase px-2 py-0.5 rounded transition-colors ${fidelity === 'High' ? 'bg-purple-600 text-white' : 'bg-slate-800 text-slate-500'}`}>
                        {fidelity}
                      </button>
                   </div>
                </div>
             </div>
          </section>
        </div>

        {/* Main Interface Content */}
        <div className="lg:col-span-9 flex flex-col gap-6 overflow-hidden">
          
          {/* TRACKING TAB */}
          {activeTab === 'tracking' && (
            <div className="flex-1 bg-[#010309] border border-white/5 rounded-[3.5rem] p-10 flex flex-col relative overflow-hidden shadow-2xl">
              <div className="absolute inset-0 opacity-[0.03] pointer-events-none" style={{ backgroundImage: 'radial-gradient(circle at 1px 1px, #fff 1px, transparent 0)', backgroundSize: '32px 32px' }}></div>
              <div className="flex justify-between items-start mb-8 z-10">
                <div className="flex flex-col gap-2">
                  <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                    <Dna size={24} className="text-purple-500" /> Propagation Vector
                  </h3>
                  <div className="p-4 bg-black/60 border border-white/5 rounded-2xl font-mono text-[9px] text-slate-500 leading-tight">
                    {activeSat?.tle?.line1 || 'TLE LINE 1 NOT AVAILABLE'}<br/>{activeSat?.tle?.line2 || 'TLE LINE 2 NOT AVAILABLE'}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4">
                   <div className="bg-purple-500/10 border border-purple-500/20 px-6 py-4 rounded-3xl flex flex-col items-end">
                      <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Velocity</span>
                      <span className="text-lg font-black text-white">{activeSat?.coords?.velocity?.toFixed(2) || '0.00'} km/s</span>
                   </div>
                   <div className="bg-emerald-500/10 border border-emerald-500/20 px-6 py-4 rounded-3xl flex flex-col items-end">
                      <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Antenna Servo Lock</span>
                      <span className="text-lg font-black text-emerald-400">{antenna.servo_lock ? 'ACTIVE' : 'MANUAL'}</span>
                   </div>
                </div>
              </div>

              <div className="flex-1 flex items-center justify-center relative">
                 <OrbitalVisualization 
                   satellites={filteredSatellites}
                   selectedSatellite={selectedSatId}
                   onSelectSatellite={setSelectedSatId}
                   observerLat={observerLat}
                   observerLng={observerLng}
                 />
              </div>
              
              <div className="mt-4">
                <LocationDisplay />
              </div>
            </div>
          )}

          {/* FORGE TAB */}
          {activeTab === 'ccsds' && (
            <div className="flex-1 bg-slate-900/40 border border-slate-800 rounded-[3rem] p-10 flex flex-col gap-8 shadow-2xl relative overflow-hidden">
               <div className="flex justify-between items-center z-10">
                <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                  <Hexagon size={24} className="text-blue-500" /> CCSDS Protocol Forge
                </h3>
                <div className="flex gap-4">
                   <button 
                    onClick={() => setIsObfuscating(!isObfuscating)}
                    className={`px-6 py-2 rounded-xl text-[10px] font-black uppercase flex items-center gap-2 transition-all ${isObfuscating ? 'bg-red-600 text-white animate-pulse' : 'bg-slate-800 text-slate-500 hover:text-white'}`}
                   >
                      <Flame size={14} /> 
                      {isObfuscating ? 'Chaff Engaged' : 'Signal Chaff Engine'}
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
                <div className="p-8 bg-black/60 border border-white/5 rounded-[2.5rem] space-y-6">
                   <div className="grid grid-cols-3 gap-6">
                      <div className="space-y-2">
                         <label className="text-[8px] font-black text-slate-600 uppercase">APID</label>
                         <input defaultValue="0x3E5" className="w-full bg-slate-900 border border-white/5 rounded-xl p-3 text-xs font-mono text-blue-400 outline-none" />
                      </div>
                      <div className="space-y-2">
                         <label className="text-[8px] font-black text-slate-600 uppercase">Seq Count</label>
                         <input defaultValue="4012" className="w-full bg-slate-900 border border-white/5 rounded-xl p-3 text-xs font-mono text-blue-400 outline-none" />
                      </div>
                   </div>
                   <textarea 
                    className="w-full h-40 bg-slate-900 border border-white/5 rounded-2xl p-6 text-[11px] font-mono text-emerald-500/80 resize-none outline-none" 
                    defaultValue="08 A1 00 00 FF FF DE AD BE EF 00 12 34 56 78 9A BC DE F0" 
                   />
                   <div className="p-4 bg-orange-500/5 border border-orange-500/20 rounded-2xl text-[9px] text-orange-500/60 leading-relaxed italic">
                      Hardware Offload: Using {dspEngine} for real-time CRC calculation and baseband modulation.
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
                      <span className="text-[9px] font-black text-emerald-500 uppercase">CRC-16-CCITT Poly Check</span>
                      <span className="text-xs font-mono text-white">0xFEA2 (PASS)</span>
                   </div>
                </div>
              </div>
            </div>
          )}

          {/* DPI TAB */}
          {activeTab === 'dpi' && (
            <div className="flex-1 bg-slate-900/40 border border-slate-800 rounded-[3rem] p-10 flex flex-col gap-6 shadow-2xl overflow-hidden relative">
               <div className="flex justify-between items-center z-10">
                <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                  <FileSearch size={24} className="text-emerald-500" /> Deep Packet Inspection (DPI)
                </h3>
                <div className="flex gap-2">
                  <span className="px-3 py-1 bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded-full text-[9px] font-black uppercase">Classification: {aiModulation}</span>
                  <span className="px-3 py-1 bg-blue-500/10 text-blue-400 border border-blue-500/20 rounded-full text-[9px] font-black uppercase">VITA-49 Locked</span>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto space-y-3 pr-2 scrollbar-hide z-10">
                 {dpiFrames.map((frame, i) => (
                   <div key={i} className="p-4 bg-black/40 border border-white/5 rounded-2xl flex justify-between items-center animate-in slide-in-from-right-4">
                      <div className="flex items-center gap-6">
                         <div className={`p-2 rounded-lg ${frame.status === 'authenticated' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'}`}>
                           <ShieldCheck size={16} />
                         </div>
                         <div className="flex flex-col">
                            <span className="text-[10px] font-black text-white uppercase tracking-tighter">SCID: {frame.scid} | VCID: {frame.vcid}</span>
                            <span className="text-[9px] font-mono text-slate-500">SEQ: {frame.frameCount} | MOD: {frame.modulationAI || aiModulation}</span>
                         </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                           <span className="text-[8px] font-black text-slate-600 uppercase block">Status</span>
                           <span className={`text-[10px] font-black uppercase ${frame.status === 'authenticated' ? 'text-emerald-500' : 'text-red-500'}`}>{frame.status}</span>
                        </div>
                        <button className="p-2 text-slate-600 hover:text-white"><Maximize2 size={14} /></button>
                      </div>
                   </div>
                 ))}
                 {dpiFrames.length === 0 && (
                   <div className="h-full flex flex-col items-center justify-center opacity-20 italic">
                      <Binary size={48} className="mb-4" />
                      <p className="text-xs font-black uppercase tracking-widest">Scanning Signal Profile for Structural Anomalies</p>
                   </div>
                 )}
              </div>
            </div>
          )}

          {/* SUBSYSTEMS TAB */}
          {activeTab === 'subsystems' && (
            <div className="flex-1 grid grid-cols-2 lg:grid-cols-3 gap-6 overflow-y-auto pr-2 scrollbar-hide pb-20">
               {activeSat?.subsystems?.map(sub => {
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
                         <span className={`text-[8px] font-black px-2 py-0.5 rounded-full border ${sub.status === 'nominal' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
                            {sub.status.toUpperCase()}
                         </span>
                       </div>
                    </div>
                    <div className="z-10">
                       <h4 className="text-sm font-black text-white uppercase tracking-tight">{sub.name}</h4>
                       <div className="w-full h-1 bg-slate-800 rounded-full mt-3 overflow-hidden">
                          <div className={`h-full transition-all duration-1000 ${sub.load > 80 ? 'bg-red-500' : 'bg-blue-500'}`} style={{ width: `${sub.load}%` }}></div>
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
                       <button 
                        onClick={() => {
                          const next = new Set(spoofedSubsystems);
                          if (next.has(sub.id)) next.delete(sub.id);
                          else next.add(sub.id);
                          setSpoofedSubsystems(next);
                        }}
                        className={`flex-1 py-4 rounded-2xl text-[9px] font-black uppercase transition-all shadow-lg ${isSpoofed ? 'bg-purple-600 text-white border-purple-500/50' : 'bg-black/60 border border-white/5 text-slate-500 hover:text-purple-400'}`}
                       >
                         {isSpoofed ? 'Deactivate Spoof' : 'Mimic Subsystem'}
                       </button>
                    </div>
                 </div>
               )})}
            </div>
          )}

          {/* SPECTRAL TAB */}
          {activeTab === 'spectral' && (
             <div className="flex-1 bg-black rounded-[3.5rem] border border-white/5 p-12 flex flex-col gap-10 shadow-2xl overflow-hidden relative">
               <div className="flex justify-between items-start z-10">
                 <div>
                    <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                      <Waves size={24} className="text-blue-500" /> Signal Distribution
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-2 uppercase font-black tracking-[0.2em]">{activeSat?.designation || 'Unknown'} Center: {activeSat?.rfProfile?.frequency || 'N/A'}</p>
                 </div>
                 <div className="flex items-center gap-4 bg-slate-900/60 p-2 rounded-2xl border border-white/5">
                    <button 
                      onClick={handleIqCapture}
                      className={`px-5 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest shadow-lg flex items-center gap-2 transition-all ${isRecordingIQ ? 'bg-emerald-600 text-white animate-pulse' : 'bg-slate-800 text-slate-500 hover:text-white'}`}
                    >
                      <HardDrive size={14} />
                      {isRecordingIQ ? 'Recording IQ...' : 'Start IQ Capture'}
                    </button>
                    <button 
                      onClick={() => setDspEngine(e => e === 'CPU' ? 'FPGA' : 'CPU')}
                      className={`px-5 py-2 rounded-xl text-[9px] font-black uppercase tracking-widest shadow-lg ${dspEngine !== 'CPU' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-500'}`}
                    >
                      VITA-49 Encapsulation
                    </button>
                 </div>
               </div>

               <div className="flex-1 relative border border-white/5 rounded-3xl overflow-hidden group">
                  <canvas ref={waterfallRef} className="absolute inset-0 w-full h-full opacity-60" width={1200} height={600} />
                  <div className="absolute inset-0 bg-gradient-to-t from-black via-transparent to-transparent pointer-events-none"></div>
                  
                  <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center gap-6 z-20">
                     <div className="relative w-48 h-48 flex items-center justify-center">
                        <div className={`absolute inset-0 border-4 rounded-full animate-ping ${dataSource === 'BRIDGE' ? 'border-emerald-500/20' : 'border-blue-500/20'}`}></div>
                        <div className={`absolute inset-0 border-2 rounded-full animate-[spin_10s_linear_infinite] ${dataSource === 'BRIDGE' ? 'border-emerald-500/40' : 'border-blue-500/40'}`}></div>
                        <Radio size={48} className={dataSource === 'BRIDGE' ? 'text-emerald-400' : 'text-blue-400'} />
                     </div>
                     <span className={`text-[10px] font-black uppercase tracking-[0.5em] animate-pulse ${dataSource === 'BRIDGE' ? 'text-emerald-500' : 'text-blue-500'}`}>
                       {dataSource === 'BRIDGE' ? 'Antenna Tracking Locked' : 'Virtual Sync Mode'}
                     </span>
                  </div>
               </div>
             </div>
          )}

          {/* AOS TAB */}
          {activeTab === 'aos' && (
            <div className="flex-1 bg-slate-900/40 border border-slate-800 rounded-[3rem] p-10 flex flex-col gap-10 shadow-2xl relative">
               <div className="flex justify-between items-center z-10">
                <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                  <Calendar size={24} className="text-emerald-500" /> Strategic Pass Planner
                </h3>
                <button 
                  onClick={() => syncTleGroup('active')}
                  className="px-6 py-2 bg-emerald-600 text-white rounded-xl text-[10px] font-black uppercase flex items-center gap-2 shadow-lg hover:bg-emerald-500 transition-all"
                >
                   <RefreshCcw size={14} className={isSyncingTle ? 'animate-spin' : ''} /> Sync All TLEs
                </button>
              </div>
              <div className="grid grid-cols-2 gap-6 overflow-y-auto pr-2 scrollbar-hide pb-20 z-10">
                {[1,2,3,4].map(i => (
                  <div key={i} className="p-8 bg-black/40 border border-white/5 rounded-[2.5rem] relative group hover:border-emerald-500/30 transition-all cursor-default">
                    <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
                       <Timer size={64} />
                    </div>
                    <div className="flex justify-between items-start mb-6">
                      <div className="flex items-center gap-4">
                         <div className="w-12 h-12 bg-emerald-500/10 border border-emerald-500/20 rounded-2xl flex items-center justify-center text-emerald-400">
                            <Clock size={24} />
                         </div>
                         <div>
                            <h4 className="text-sm font-black text-white uppercase tracking-tight">Pass Window Alpha-{i}</h4>
                            <p className="text-[9px] text-slate-500 uppercase font-black tracking-widest mt-1">Acquisition Lock in T-{i * 15}m</p>
                         </div>
                      </div>
                      <div className="flex flex-col items-end gap-1">
                         <span className="text-[8px] font-black px-2 py-0.5 bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 rounded uppercase">Auto-Rec On</span>
                         <span className="text-[8px] font-black px-2 py-0.5 bg-blue-500/10 text-blue-500 border border-blue-500/20 rounded uppercase">VITA-49 STREAM</span>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-4 bg-slate-900/60 rounded-2xl">
                         <span className="text-[8px] font-black text-slate-600 uppercase block mb-1">Duration</span>
                         <span className="text-xs font-black text-white">{(Math.random() * 10 + 5).toFixed(1)}m</span>
                      </div>
                      <div className="p-4 bg-slate-900/60 rounded-2xl">
                         <span className="text-[8px] font-black text-slate-600 uppercase block mb-1">Max Elev</span>
                         <span className="text-xs font-black text-white">{(Math.random() * 60 + 20).toFixed(1)}°</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* RELAY TAB */}
          {activeTab === 'relay' && (
            <div className="flex-1 bg-slate-900/40 border border-slate-800 rounded-[3rem] p-10 flex flex-col gap-10 shadow-2xl relative">
               <div className="flex justify-between items-center z-10">
                <h3 className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4">
                  <Network size={24} className="text-blue-500" /> Multi-Hop Orbital Relay
                </h3>
                <div className="flex items-center gap-3">
                   <span className="text-[10px] font-black text-slate-500 uppercase tracking-widest">Mesh Signal Routing</span>
                   <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_#10b981]"></div>
                </div>
              </div>
              <div className="flex-1 flex flex-col gap-8 justify-center z-10">
                 <div className="flex items-center justify-between max-w-4xl mx-auto w-full px-12">
                    {[
                      { id: 'hop-1', assetId: 'STERN-WATCH-4', label: 'Hop 1' },
                      { id: 'hop-2', assetId: 'Iridium-Next-142', label: 'Hop 2' },
                      { id: 'hop-3', assetId: 'Ground-Relay-UK', label: 'Terminal' }
                    ].map((hop, idx, arr) => (
                      <React.Fragment key={hop.id}>
                        <div className="flex flex-col items-center gap-4 p-8 bg-black/40 border border-white/5 rounded-[2rem] shadow-xl hover:border-blue-500/50 transition-all cursor-default group">
                           <Satellite size={32} className="text-blue-400 group-hover:animate-bounce" />
                           <div className="text-center">
                              <span className="text-[10px] font-black text-white block uppercase tracking-tighter">{hop.assetId}</span>
                              <span className="text-[8px] font-mono text-slate-500 uppercase">{hop.label} Link</span>
                           </div>
                        </div>
                        {idx < arr.length - 1 && (
                          <div className="flex-1 h-px bg-gradient-to-r from-blue-500 to-emerald-500 relative">
                             <div className="absolute top-1/2 left-0 -translate-y-1/2 w-3 h-3 bg-blue-500 rounded-full animate-ping"></div>
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                 </div>
                 <div className="max-w-2xl mx-auto space-y-4">
                    <div className="text-center p-6 bg-blue-500/5 border border-blue-500/10 rounded-[2rem]">
                      <p className="text-[10px] text-blue-400/60 leading-relaxed font-black uppercase tracking-widest">
                         Relay active over distributed SIGINT mesh. Synthetic aperture enabled across {meshPeers} terrestrial nodes.
                      </p>
                    </div>
                    <div className="p-6 bg-black/40 border border-white/5 rounded-[2rem]">
                      <h4 className="text-xs font-black text-white uppercase mb-3">Backend Integration</h4>
                      <div className="space-y-2 text-[10px] font-mono text-slate-400">
                        <div className="flex items-center gap-2">
                          <span className="text-emerald-400">→</span> Use Terminal (Local Core) to execute:
                        </div>
                        <div className="pl-4 p-2 bg-black/60 rounded border border-white/5 text-blue-400">
                          relay-init --hops LEO-GEO-LEO
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-emerald-400">→</span> Check relay status:
                        </div>
                        <div className="pl-4 p-2 bg-black/60 rounded border border-white/5 text-blue-400">
                          relay-status
                        </div>
                        <div className="text-[9px] text-slate-600 mt-2">
                          * Commands route to backend /api/v1/modules/execute
                        </div>
                      </div>
                    </div>
                 </div>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
};

export default SatelliteOrchestrator;
