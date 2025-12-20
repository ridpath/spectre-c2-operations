
import React, { useState } from 'react';
import { DROPPER_TEMPLATES } from '../constants';
import { DropperTemplate, QuantumForgeConfig } from '../types';
import { Copy, Zap, ShieldAlert, Cpu, Terminal as TerminalIcon, FlaskConical, Binary, Layers, EyeOff } from 'lucide-react';
import { generateDropper } from '../services/geminiService';

interface DropperManagerProps {
  onInsertCode: (code: string) => void;
}

const DropperManager: React.FC<DropperManagerProps> = ({ onInsertCode }) => {
  const [lhost, setLhost] = useState('10.10.14.12');
  const [lport, setLport] = useState('443');
  const [customDropper, setCustomDropper] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [targetType, setTargetType] = useState('Windows 11');
  
  // Fix: Added missing properties 'indirectSyscalls' and 'stackSpoofing' to satisfy QuantumForgeConfig interface
  const [forgeConfig, setForgeConfig] = useState<QuantumForgeConfig>({
    obfuscation: 'quantum-random',
    heapStealth: true,
    amsiBypass: true,
    etwPatching: true,
    indirectSyscalls: true,
    stackSpoofing: true,
    executionMode: 'reflective'
  });

  const getProcessedTemplate = (template: string) => {
    let code = template
      .replace(/{{LHOST}}/g, lhost)
      .replace(/{{LPORT}}/g, lport);
    
    // Simulate QuantumForge assembly process
    if (forgeConfig.amsiBypass) code = `[System.Runtime.InteropServices.Marshal]::WriteInt32(...) # AMSI Bypass Staged\n` + code;
    if (forgeConfig.obfuscation === 'polymorphic') code = `# Polymorphic Stub\n` + code.split('').reverse().join(''); // Mock obfuscation
    
    return code;
  };

  const handleGenerateAI = async () => {
    setIsGenerating(true);
    const result = await generateDropper(`${targetType} (Forge Mode: ${forgeConfig.executionMode})`, lhost, lport);
    setCustomDropper(result);
    setIsGenerating(false);
  };

  const toggleForgeOption = (key: keyof QuantumForgeConfig) => {
    setForgeConfig(prev => ({ ...prev, [key]: !prev[key] as any }));
  };

  return (
    <div className="flex flex-col h-full gap-6 overflow-hidden">
      <header className="flex flex-col gap-1">
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <FlaskConical size={20} /> QuantumForge Assembly
        </h2>
        <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold">Stealth Payload Generation System</p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 overflow-hidden">
        {/* Assembly Controls */}
        <div className="lg:col-span-4 flex flex-col gap-6 overflow-y-auto pr-2">
          <section className="bg-slate-900/50 p-6 rounded-3xl border border-slate-800 space-y-6">
            <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
              <Layers size={14} className="text-blue-500" /> Staging Parameters
            </h3>
            
            <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-[9px] font-black text-slate-600 uppercase">Listener Link (LHOST)</label>
                <input value={lhost} onChange={e => setLhost(e.target.value)} className="w-full bg-black/40 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-400 focus:border-emerald-500 transition-all outline-none" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-600 uppercase">Port (LPORT)</label>
                  <input value={lport} onChange={e => setLport(e.target.value)} className="w-full bg-black/40 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-400" />
                </div>
                <div className="space-y-1">
                  <label className="text-[9px] font-black text-slate-600 uppercase">Build Target</label>
                  <select value={targetType} onChange={e => setTargetType(e.target.value)} className="w-full bg-black/40 border border-slate-800 rounded-xl p-3 text-xs text-slate-300 outline-none">
                    <option>Win11_X64</option>
                    <option>Win10_X64</option>
                    <option>Server22</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="h-px bg-white/5 my-6"></div>

            <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
              <EyeOff size={14} className="text-emerald-500" /> Stealth Toggles
            </h3>
            
            <div className="grid grid-cols-2 gap-2">
              {[
                { id: 'amsiBypass', label: 'AMSI Bypass', color: 'emerald' },
                { id: 'etwPatching', label: 'ETW Patch', color: 'blue' },
                { id: 'heapStealth', label: 'Heap Stealer', color: 'purple' },
              ].map(opt => (
                <button 
                  key={opt.id}
                  onClick={() => toggleForgeOption(opt.id as any)}
                  className={`px-3 py-2 rounded-xl text-[9px] font-black uppercase transition-all border 
                    ${(forgeConfig as any)[opt.id] 
                      ? `bg-${opt.color}-500/10 border-${opt.color}-500/30 text-${opt.color}-400` 
                      : 'bg-slate-900 border-slate-800 text-slate-600'}`}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            <button 
              onClick={handleGenerateAI}
              disabled={isGenerating}
              className="w-full py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl text-xs font-black transition-all flex items-center justify-center gap-2 shadow-xl shadow-emerald-900/30 group"
            >
              {isGenerating ? <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" /> : <Binary size={18} className="group-hover:rotate-45 transition-transform" />}
              Assemble Custom Agent
            </button>
          </section>
        </div>

        {/* Templates & Output */}
        <div className="lg:col-span-8 overflow-y-auto space-y-6 pb-10">
          <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {DROPPER_TEMPLATES.map(tpl => {
              const code = getProcessedTemplate(tpl.template);
              return (
                <div key={tpl.id} className="bg-slate-900/40 p-5 rounded-3xl border border-slate-800 hover:border-emerald-500/30 transition-all flex flex-col group relative">
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <h4 className="text-[11px] font-black text-slate-100 uppercase tracking-tight">{tpl.name}</h4>
                      <div className="flex gap-2 mt-2">
                        <span className="text-[8px] font-black uppercase px-2 py-0.5 bg-black/60 text-slate-500 rounded-md border border-white/5">{tpl.evasionLevel} Evasion</span>
                      </div>
                    </div>
                    <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                      <button onClick={() => navigator.clipboard.writeText(code)} className="p-2 bg-slate-800 text-slate-400 hover:text-emerald-400 rounded-lg">
                        <Copy size={14} />
                      </button>
                      <button onClick={() => onInsertCode(code)} className="p-2 bg-emerald-600/10 text-emerald-500 hover:bg-emerald-600 hover:text-white rounded-lg">
                        <TerminalIcon size={14} />
                      </button>
                    </div>
                  </div>
                  <p className="text-[10px] text-slate-500 mb-6 flex-1 italic leading-relaxed">{tpl.description}</p>
                  <div className="p-4 bg-black/60 rounded-xl font-mono text-[9px] text-emerald-500/70 border border-white/5 break-all max-h-20 overflow-hidden relative">
                    {code}
                    <div className="absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-black/80 to-transparent"></div>
                  </div>
                </div>
              );
            })}
          </section>

          {customDropper && (
            <section className="bg-emerald-500/5 border border-emerald-500/20 rounded-3xl p-6 animate-in zoom-in duration-300">
              <div className="flex justify-between items-center mb-4">
                <h3 className="text-xs font-black text-emerald-400 uppercase tracking-widest flex items-center gap-2">
                  <Zap size={14} /> Synthetic Quantum Agent Result
                </h3>
                <button onClick={() => onInsertCode(customDropper)} className="px-4 py-2 bg-emerald-600 text-white rounded-full text-[10px] font-black uppercase tracking-widest">
                  Deploy Immediately
                </button>
              </div>
              <pre className="p-4 bg-black rounded-xl border border-emerald-900/30 font-mono text-[10px] text-emerald-100 whitespace-pre-wrap leading-loose">
                {customDropper}
              </pre>
            </section>
          )}
        </div>
      </div>
    </div>
  );
};

export default DropperManager;
