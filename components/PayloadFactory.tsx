
import React, { useState } from 'react';
import { DROPPER_TEMPLATES } from '../constants';
import { DropperTemplate, QuantumForgeConfig, PayloadFormat } from '../types';
import { 
  Copy, 
  Zap, 
  Cpu, 
  Terminal as TerminalIcon, 
  Binary, 
  Layers, 
  EyeOff, 
  ShieldCheck, 
  Box, 
  HardDrive, 
  FileCode,
  Wifi,
  Clock,
  Settings2,
  Lock,
  Target,
  Loader2,
  Link,
  Disc,
  Skull,
  Activity,
  UserPlus,
  Shield,
  Fingerprint
} from 'lucide-react';
import { generateDropper } from '../services/geminiService';

interface PayloadFactoryProps {
  onInsertCode: (code: string) => void;
}

const PayloadFactory: React.FC<PayloadFactoryProps> = ({ onInsertCode }) => {
  const [lhost, setLhost] = useState('10.10.14.12');
  const [lport, setLport] = useState('443');
  const [jitter, setJitter] = useState(25);
  const [sleep, setSleep] = useState(5);
  const [arch, setArch] = useState<'x64' | 'x86'>('x64');
  const [targetProcess, setTargetProcess] = useState('lsass.exe');
  const [customArtifact, setCustomArtifact] = useState('');
  const [isSynthesizing, setIsSynthesizing] = useState(false);
  const [selectedFormat, setSelectedFormat] = useState<PayloadFormat>('shellcode');
  
  const [forgeConfig, setForgeConfig] = useState<QuantumForgeConfig & { sleepMasking: boolean; ppidSpoofing: boolean; blockDlls: boolean; heaplessExecution: boolean }>({
    obfuscation: 'quantum-random',
    heapStealth: true,
    amsiBypass: true,
    etwPatching: true,
    indirectSyscalls: true,
    stackSpoofing: true,
    executionMode: 'heapless-isolation',
    sleepMasking: true,
    ppidSpoofing: true,
    blockDlls: true,
    heaplessExecution: true,
    vectorChannel: 'multiplexed'
  });

  const handleSynthesize = async () => {
    setIsSynthesizing(true);
    const context = `Industrial Grade Stager Generation. 
    Designation: HEAPLESS_PHANTOM_VECTOR.
    Format: ${selectedFormat}, 
    Arch: ${arch},
    Target Process: ${targetProcess},
    Vector Channel: ${forgeConfig.vectorChannel},
    Advanced Modules: [Heapless Memory Isolation, Indirect Syscalls, Sleep Encryption, PPID Spoofing, EDR Hook Evasion]`;
              
    const result = await generateDropper(context, lhost, lport);
    setCustomArtifact(result);
    setIsSynthesizing(false);
  };

  const toggleForgeOption = (key: string) => {
    setForgeConfig(prev => ({ ...prev, [key]: !prev[key as keyof typeof prev] as any }));
  };

  const formats: {id: PayloadFormat, label: string, icon: any}[] = [
    { id: 'shellcode', label: 'Raw Vector', icon: <Binary size={14} /> },
    { id: 'exe', label: 'Service Wrapper', icon: <HardDrive size={14} /> },
    { id: 'dll', label: 'Reflective DLL', icon: <Box size={14} /> },
    { id: 'service-exe', label: 'Daemon Binary', icon: <ShieldCheck size={14} /> },
    { id: 'powershell', label: 'In-Memory Script', icon: <TerminalIcon size={14} /> }
  ];

  return (
    <div className="flex flex-col h-full gap-6 overflow-hidden animate-in fade-in duration-700">
      <header className="flex flex-col gap-1">
        <h2 className="text-2xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-3">
          <Skull size={24} /> Artifact Foundry & Synthesis
        </h2>
        <p className="text-[10px] text-slate-500 uppercase tracking-[0.25em] font-black mt-1">Professional Stealth Engineering Laboratory</p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 overflow-hidden">
        {/* Synthesis Controller */}
        <div className="lg:col-span-4 flex flex-col gap-6 overflow-y-auto pr-2 scrollbar-hide">
          <section className="bg-slate-900/40 p-6 rounded-[2rem] border border-slate-800 space-y-6 shadow-2xl relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-[1px] bg-emerald-500/20"></div>
            
            <div className="flex items-center justify-between">
              <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
                <Settings2 size={14} className="text-blue-500" /> Tactical Parameters
              </h3>
              <div className="flex bg-black/60 p-1 rounded-lg border border-white/5">
                <button onClick={() => setArch('x64')} className={`px-3 py-1 text-[9px] font-black rounded ${arch === 'x64' ? 'bg-emerald-600 text-white' : 'text-slate-500'}`}>x64</button>
                <button onClick={() => setArch('x86')} className={`px-3 py-1 text-[9px] font-black rounded ${arch === 'x86' ? 'bg-emerald-600 text-white' : 'text-slate-500'}`}>x86</button>
              </div>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-[8px] font-black text-slate-600 uppercase tracking-tighter">Signal Target</label>
                  <input value={lhost} onChange={e => setLhost(e.target.value)} className="w-full bg-black/60 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-400 focus:border-emerald-500 outline-none" />
                </div>
                <div className="space-y-1">
                  <label className="text-[8px] font-black text-slate-600 uppercase tracking-tighter">Signal Port</label>
                  <input value={lport} onChange={e => setLport(e.target.value)} className="w-full bg-black/60 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-400 focus:border-emerald-500 outline-none" />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-[8px] font-black text-slate-600 uppercase flex items-center gap-2 tracking-tighter">
                  <UserPlus size={10} /> Injection Vector (Process Name)
                </label>
                <input value={targetProcess} onChange={e => setTargetProcess(e.target.value)} className="w-full bg-black/60 border border-slate-800 rounded-xl p-3 text-xs font-mono text-blue-400" />
              </div>

              <div className="grid grid-cols-2 gap-4">
                 <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <label className="text-[8px] font-black text-slate-600 uppercase">Sleep</label>
                    <span className="text-[9px] font-mono text-emerald-400">{sleep}s</span>
                  </div>
                  <input type="range" min="1" max="300" value={sleep} onChange={e => setSleep(parseInt(e.target.value))} className="w-full accent-emerald-500" />
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <label className="text-[8px] font-black text-slate-600 uppercase">Jitter</label>
                    <span className="text-[9px] font-mono text-blue-400">{jitter}%</span>
                  </div>
                  <input type="range" min="0" max="100" value={jitter} onChange={e => setJitter(parseInt(e.target.value))} className="w-full accent-blue-500" />
                </div>
              </div>
            </div>

            <div className="h-px bg-white/5"></div>

            <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
              <Shield size={14} className="text-red-500" /> Stealth Configuration
            </h3>
            
            <div className="grid grid-cols-2 gap-2">
              {[
                { id: 'heaplessExecution', label: 'Heapless', color: 'emerald' },
                { id: 'indirectSyscalls', label: 'Syscalls', color: 'red' },
                { id: 'sleepMasking', label: 'Masking', color: 'blue' },
                { id: 'stackSpoofing', label: 'Stack Spoof', color: 'purple' },
                { id: 'ppidSpoofing', label: 'PPID Spoof', color: 'yellow' },
                { id: 'blockDlls', label: 'Block DLLs', color: 'orange' },
              ].map(opt => (
                <button 
                  key={opt.id}
                  onClick={() => toggleForgeOption(opt.id)}
                  className={`px-3 py-2 rounded-xl text-[8px] font-black uppercase tracking-widest transition-all border flex items-center justify-between
                    ${(forgeConfig as any)[opt.id] 
                      ? `bg-${opt.color}-500/10 border-${opt.color}-500/40 text-${opt.color}-400` 
                      : 'bg-black/40 border-slate-800 text-slate-600'}`}
                >
                  {opt.label}
                  <div className={`w-1 h-1 rounded-full ${(forgeConfig as any)[opt.id] ? `bg-${opt.color}-500` : 'bg-slate-800'}`}></div>
                </button>
              ))}
            </div>

            <button 
              onClick={handleSynthesize}
              disabled={isSynthesizing}
              className="w-full py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all flex items-center justify-center gap-3 shadow-xl shadow-emerald-900/40 disabled:opacity-50"
            >
              {isSynthesizing ? <Loader2 size={16} className="animate-spin" /> : <Lock size={16} />}
              {isSynthesizing ? 'Generating Vector...' : 'Finalize Synthesis'}
            </button>
          </section>
        </div>

        {/* Output Display */}
        <div className="lg:col-span-8 flex flex-col gap-6 overflow-hidden">
          <section className="bg-slate-900/20 p-4 rounded-[2rem] border border-white/5 flex flex-wrap gap-2">
            {formats.map(f => (
              <button
                key={f.id}
                onClick={() => setSelectedFormat(f.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-xl text-[9px] font-black uppercase transition-all border ${
                  selectedFormat === f.id 
                  ? 'bg-blue-600 border-blue-400 text-white shadow-lg' 
                  : 'bg-black/40 border-slate-800 text-slate-500 hover:border-slate-600 hover:text-slate-300'
                }`}
              >
                {f.icon} {f.label}
              </button>
            ))}
          </section>

          <div className="flex-1 overflow-y-auto pr-2 space-y-4 scrollbar-hide pb-20">
             {customArtifact ? (
               <div className="bg-black border border-emerald-500/20 rounded-[2rem] p-8 animate-in zoom-in duration-500 shadow-2xl relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-8 opacity-5">
                    <Activity size={100} className="text-emerald-500" />
                  </div>
                  <div className="relative z-10">
                    <div className="flex justify-between items-center mb-6">
                      <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center text-emerald-400 border border-emerald-500/20">
                          <Fingerprint size={24} />
                        </div>
                        <div>
                          <h3 className="text-lg font-black text-white uppercase tracking-tighter">Synthetic Vector Result</h3>
                          <p className="text-[8px] text-emerald-500/60 font-black uppercase tracking-widest">Type: {selectedFormat} • Arch: {arch}</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => navigator.clipboard.writeText(customArtifact)} className="px-4 py-2 bg-slate-800 text-slate-300 rounded-xl text-[9px] font-black uppercase hover:bg-slate-700 transition-all">Copy</button>
                        <button onClick={() => onInsertCode(customArtifact)} className="px-4 py-2 bg-emerald-600 text-white rounded-xl text-[9px] font-black uppercase shadow-lg shadow-emerald-900/40 hover:bg-emerald-500 transition-all">Stage Beacon</button>
                      </div>
                    </div>
                    <pre className="p-6 bg-slate-900/50 rounded-2xl border border-white/5 font-mono text-[10px] text-emerald-100/80 whitespace-pre-wrap leading-relaxed max-h-96 overflow-y-auto custom-scrollbar">
                      {customArtifact}
                    </pre>
                  </div>
               </div>
             ) : (
               <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {DROPPER_TEMPLATES.map(tpl => (
                    <div key={tpl.id} className="bg-slate-900/40 p-5 rounded-3xl border border-slate-800 hover:border-emerald-500/30 transition-all flex flex-col group relative overflow-hidden backdrop-blur-sm">
                      <div className="flex justify-between items-start mb-4">
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg bg-black/60 border border-white/5 text-slate-400">
                             <Binary size={14} />
                          </div>
                          <div>
                            <h4 className="text-[10px] font-black text-slate-100 uppercase tracking-widest">{tpl.name}</h4>
                            <span className="text-[8px] font-black uppercase text-slate-500">{tpl.targetOS} Optimized</span>
                          </div>
                        </div>
                        <button 
                          onClick={() => onInsertCode(tpl.template)} 
                          className="p-2 bg-emerald-600/10 text-emerald-500 rounded-lg hover:bg-emerald-600 hover:text-white transition-all opacity-0 group-hover:opacity-100"
                        >
                          <TerminalIcon size={14} />
                        </button>
                      </div>
                      <p className="text-[9px] text-slate-500 mb-4 flex-1 italic">{tpl.description}</p>
                      <div className="p-3 bg-black/40 rounded-xl font-mono text-[8px] text-emerald-500/40 border border-white/5 break-all h-16 overflow-hidden relative">
                        {tpl.template}
                        <div className="absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-black to-transparent"></div>
                      </div>
                    </div>
                  ))}
               </div>
             )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PayloadFactory;
