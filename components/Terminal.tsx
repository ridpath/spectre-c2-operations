
import React, { useState, useRef, useEffect, useImperativeHandle, forwardRef } from 'react';
import { WinRMConnection } from '../types';
import { 
  Terminal as TerminalIcon, 
  Send, 
  Cpu, 
  Trash2, 
  Zap, 
  Loader2, 
  Monitor, 
  Globe, 
  ShieldAlert, 
  ShieldCheck,
  Eye,
  Lock,
  Search,
  Key,
  Database,
  Wifi,
  Workflow
} from 'lucide-react';
import { analyzeCommandOutput } from '../services/geminiService';
import { useTerminal } from '../hooks/useTerminal';
import { ShellContext } from '../services/commandService';

export interface TerminalHandle {
  insertCommand: (cmd: string) => void;
}

interface TerminalProps {
  connection: WinRMConnection | null;
  onCommand: (cmd: string, context: ShellContext) => Promise<string>;
}

const Terminal = forwardRef<TerminalHandle, TerminalProps>(({ connection, onCommand }, ref) => {
  const terminal = useTerminal();
  const [input, setInput] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [shellContext, setShellContext] = useState<ShellContext>('remote');
  const [opsecRisk, setOpsecRisk] = useState<'low' | 'medium' | 'high'>('low');
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useImperativeHandle(ref, () => ({
    insertCommand: (cmd: string) => {
      setInput(cmd);
      inputRef.current?.focus();
    }
  }));

  useEffect(() => {
    const cmd = input.toLowerCase();
    if (cmd.includes('net user') || cmd.includes('mimikatz') || cmd.includes('hashdump') || cmd.includes('sekurlsa')) {
      setOpsecRisk('high');
    } else if (cmd.includes('ls') || cmd.includes('dir') || cmd.includes('ipconfig') || cmd.includes('whoami')) {
      setOpsecRisk('low');
    } else if (cmd !== '') {
      setOpsecRisk('medium');
    } else {
      setOpsecRisk('low');
    }
  }, [input]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [terminal.lines]);

  const handleCommand = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!input.trim() || terminal.isExecuting) return;
    
    if (shellContext === 'remote' && !connection) {
      terminal.addLine('error', 'SYSTEM ERROR: NO ACTIVE SIGNAL BRIDGE ESTABLISHED. SELECT A BEACON FROM THE NEXUS MAP OR SIDEBAR.');
      return;
    }

    const cmd = input.trim();
    setInput('');
    terminal.setIsExecuting(true);
    
    const timestamp = new Date().toLocaleTimeString([], { hour12: false });
    const prompt = shellContext === 'local' 
      ? `[${timestamp}] spectre@core:~$ ${cmd}` 
      : `[${timestamp}] ${connection?.username}@${connection?.host}> ${cmd}`;

    terminal.addLine('input', prompt);

    try {
      const result = await onCommand(cmd, shellContext);
      terminal.addLine('output', result);
    } catch (err: any) {
      terminal.addLine('error', `TRANSMISSION FAILED: ${err.message || 'UNKNOWN EXCEPTION'}`);
    } finally {
      terminal.setIsExecuting(false);
    }
  };

  const runAnalysis = async () => {
    const lastOutput = terminal.lines.slice().reverse().find(l => l.type === 'output');
    const lastInput = terminal.lines.slice().reverse().find(l => l.type === 'input');
    
    if (!lastOutput || !lastInput) return;

    setIsAnalyzing(true);
    terminal.addLine('system', '>> SPECTRE INTELLIGENCE ENGINE INITIALIZING...');
    
    const analysis = await analyzeCommandOutput(lastInput.content, lastOutput.content);
    terminal.addLine('system', analysis);
    terminal.addLine('system', '>> INTEL ANALYSIS COMPLETE.');
    setIsAnalyzing(false);
  };

  const shortcuts = [
    { label: 'Integrity Check', cmd: 'whoami /priv', icon: <ShieldCheck size={10} /> },
    { label: 'Survey Network', cmd: 'ipconfig /all', icon: <Search size={10} /> },
    { label: 'System Info', cmd: '[System.Environment]::OSVersion', icon: <Database size={10} /> },
    { label: 'Process Check', cmd: 'Get-Process | Select-Object Name, Id, SessionId', icon: <Eye size={10} /> },
    { label: 'Dump SAM', cmd: 'invoke-mimikatz -cmd "lsadump::sam"', icon: <Key size={10} />, risk: 'high' },
  ];

  return (
    <div className="flex flex-col h-full bg-[#000000] rounded-3xl border border-slate-800 shadow-2xl overflow-hidden group/term relative">
      {/* OpSec HUD Overlay */}
      <div className="absolute top-24 right-8 z-10 flex flex-col gap-3 pointer-events-none opacity-40 group-hover/term:opacity-100 transition-opacity">
        <div className="bg-black/80 border border-white/5 p-4 rounded-2xl flex flex-col gap-2 backdrop-blur-md min-w-[180px]">
          <div className="flex items-center justify-between">
            <span className="text-[8px] font-black uppercase text-slate-500 tracking-widest">OpSec State</span>
            <div className={`w-2 h-2 rounded-full animate-pulse ${
              opsecRisk === 'high' ? 'bg-red-500 shadow-[0_0_10px_#ef4444]' :
              opsecRisk === 'medium' ? 'bg-yellow-500 shadow-[0_0_10px_#f59e0b]' :
              'bg-emerald-500 shadow-[0_0_10px_#10b981]'
            }`}></div>
          </div>
          <div className="text-[10px] font-black uppercase tracking-tight text-white">
            Risk: <span className={
              opsecRisk === 'high' ? 'text-red-400' :
              opsecRisk === 'medium' ? 'text-yellow-400' :
              'text-emerald-400'
            }>{opsecRisk}</span>
          </div>
          <div className="h-px bg-white/5 w-full"></div>
          {connection && (
            <div className="flex flex-col gap-1">
               <span className="text-[8px] font-black uppercase text-slate-500">WinRM Context</span>
               <div className="flex items-center gap-2 text-[9px] font-mono text-emerald-400">
                  <Workflow size={10} /> {connection.authMethod} Encryption
               </div>
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center justify-between px-6 py-4 bg-[#0b1120] border-b border-white/5 backdrop-blur-xl">
        <div className="flex items-center gap-4">
          <div className="flex bg-black/60 p-1.5 rounded-2xl border border-white/10 shadow-inner">
            <button 
              onClick={() => setShellContext('local')}
              className={`flex items-center gap-2 px-4 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${
                shellContext === 'local' ? 'bg-blue-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <Monitor size={12} /> Local Core
            </button>
            <button 
              onClick={() => setShellContext('remote')}
              className={`flex items-center gap-2 px-4 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-widest transition-all ${
                shellContext === 'remote' ? 'bg-emerald-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <Globe size={12} /> Remote WinRM
            </button>
          </div>

          <div className="h-6 w-[1px] bg-white/10 mx-2"></div>
          
          <div className="flex flex-col">
            <span className="text-[8px] font-black text-slate-500 uppercase tracking-widest mb-0.5">Active Channel</span>
            <span className="text-[10px] font-mono font-bold text-slate-300">
              {shellContext === 'local' ? 'OPS-CORE-STATION' : connection ? `WINRM: ${connection.host}` : 'AWAITING PEER SIGNAL'}
            </span>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <button 
            onClick={runAnalysis}
            disabled={isAnalyzing || terminal.lines.length === 0}
            className="flex items-center gap-2 px-4 py-2 text-[10px] font-black uppercase tracking-widest text-emerald-400 bg-emerald-400/5 border border-emerald-500/20 hover:bg-emerald-400/10 rounded-xl transition-all disabled:opacity-30"
          >
            <Zap size={12} className={isAnalyzing ? 'animate-spin' : ''} />
            {isAnalyzing ? 'Processing Signal...' : 'Gemini Intel Analyze'}
          </button>
          <button 
            onClick={terminal.clearLines}
            className="p-2 text-slate-600 hover:text-red-400 hover:bg-red-400/5 rounded-xl transition-all"
            title="Purge Scrollback"
          >
            <Trash2 size={16} />
          </button>
        </div>
      </div>

      <div 
        ref={scrollRef}
        className="flex-1 p-8 overflow-y-auto font-mono text-[14px] space-y-4 leading-relaxed scrollbar-thin scrollbar-thumb-slate-800"
      >
        {terminal.lines.length === 0 && (
          <div className="flex flex-col gap-2">
            <div className="text-emerald-500/40 text-[10px] font-black uppercase tracking-[0.5em] pb-4 border-b border-white/5">
              [ SPECTRE C2 WINRM SHELL ]
            </div>
            <div className="text-slate-800 text-[10px] font-mono italic">
              * Initializing WinRM Secure Transport over SOCKS5h...<br/>
              * Validating NTLM/Kerberos session tokens...<br/>
              * Signal Core ready for transmission.<br/><br/>
              Type 'help' for command reference.
            </div>
          </div>
        )}
        {terminal.lines.map(line => (
          <div key={line.id} className={`whitespace-pre-wrap animate-in fade-in slide-in-from-left-2 duration-300 ${
            line.type === 'input' ? (shellContext === 'local' ? 'text-blue-400' : 'text-emerald-400') + ' font-bold flex items-start gap-3' : 
            line.type === 'error' ? 'text-red-400 bg-red-400/5 p-4 rounded-2xl border border-red-400/20 my-2 font-mono text-xs' :
            line.type === 'system' ? 'text-blue-200 italic border-l-2 border-blue-500/30 pl-6 my-6 py-2 bg-blue-500/5 rounded-r-2xl' : 
            'text-slate-300 pl-4'
          }`}>
            {line.type === 'input' && <div className="mt-1.5 shrink-0"><TerminalIcon size={12} /></div>}
            {line.content}
          </div>
        ))}
      </div>

      {/* WinRM Native Quick Action Ribbon */}
      <div className="px-6 py-3 bg-[#0b1120]/50 border-t border-white/5 flex gap-2 overflow-x-auto scrollbar-hide">
         <span className="text-[8px] font-black text-slate-600 uppercase tracking-widest self-center mr-2">WinRM Macros:</span>
         {shortcuts.map(s => (
           <button
             key={s.label}
             onClick={() => setInput(s.cmd)}
             className={`px-3 py-1.5 rounded-lg text-[9px] font-black uppercase tracking-widest flex items-center gap-2 border transition-all whitespace-nowrap ${
               s.risk === 'high' 
                 ? 'bg-red-500/10 border-red-500/30 text-red-400 hover:bg-red-500/20' 
                 : 'bg-white/5 border-white/5 text-slate-400 hover:text-white hover:border-white/20'
             }`}
           >
             {s.icon} {s.label}
           </button>
         ))}
      </div>

      <form onSubmit={handleCommand} className="p-6 bg-black flex gap-6 items-center">
        <div className={`flex items-center gap-3 font-black text-[10px] tracking-widest ${shellContext === 'local' ? 'text-blue-500' : 'text-emerald-500'}`}>
          {terminal.isExecuting ? <Loader2 size={16} className="animate-spin" /> : <Cpu size={16} />}
          {shellContext === 'local' ? 'CORE' : 'WINRM'}
        </div>
        <div className="flex-1 relative">
           <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={terminal.isExecuting}
            className="w-full bg-transparent border-none focus:ring-0 text-slate-100 text-sm font-mono placeholder-slate-800"
            placeholder={connection ? `Direct shell access to ${connection.host}...` : "Initialize signal core..."}
            autoFocus
          />
          {input && (
            <div className={`absolute right-0 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-[8px] font-black uppercase ${
              opsecRisk === 'high' ? 'bg-red-500 text-white' : 'bg-slate-800 text-slate-400'
            }`}>
              {opsecRisk} RISK
            </div>
          )}
        </div>
        <button 
          type="submit"
          disabled={!input.trim() || terminal.isExecuting}
          className={`px-8 py-3 rounded-2xl text-[10px] font-black uppercase tracking-[0.2em] disabled:opacity-20 transition-all flex items-center gap-2 shadow-xl ${
            shellContext === 'local' ? 'bg-blue-600 hover:bg-blue-500' : 'bg-emerald-600 hover:bg-emerald-500 shadow-emerald-900/40'
          } text-white`}
        >
          {terminal.isExecuting ? 'TRANSMITTING...' : 'EXECUTE'} <Send size={12} />
        </button>
      </form>
    </div>
  );
});

export default Terminal;
