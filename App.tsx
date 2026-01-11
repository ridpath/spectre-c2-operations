
import React, { useState, useRef, useEffect } from 'react';
import ConnectionSidebar from './components/ConnectionSidebar';
import Terminal, { TerminalHandle } from './components/Terminal';
import NeuralEngagementMap from './components/NeuralEngagementMap';
import PayloadFactory from './components/PayloadFactory';
import ModuleBrowser from './components/ModuleBrowser';
import EvidenceVault from './components/EvidenceVault';
import ProfileEditor from './components/ProfileEditor';
import LoginScreen from './components/LoginScreen';
import OperatorSettings from './components/OperatorSettings';
import LabAssistant from './components/LabAssistant';
import AutonomousOrchestrator from './components/AutonomousOrchestrator';
import SpectrumStudio from './components/SpectrumStudio';
import OpSecMonitor from './components/OpSecMonitor';
import TorEgressMonitor from './components/TorEgressMonitor';
import APTOrchestrator from './components/APTOrchestrator';
import PivotOrchestrator from './components/PivotOrchestrator';
import VulnerabilityValidator from './components/VulnerabilityValidator';
import SatelliteOrchestrator from './components/SatelliteOrchestrator';
import FirmwareStudio from './components/FirmwareStudio';
import CryptanalysisLab from './components/CryptanalysisLab';
import SatelliteExploitOrchestrator from './components/SatelliteExploitOrchestrator';
import LinkBudgetCalculator from './components/LinkBudgetCalculator';

import { useC2 } from './hooks/useC2';
import { executeCommand, ShellContext } from './services/commandService';
import { 
  Terminal as TerminalIcon, 
  Share2, 
  Binary, 
  Globe, 
  Settings, 
  Shield, 
  Zap,
  LogOut,
  Ghost,
  Wifi,
  ShieldAlert,
  Target,
  Database,
  Network,
  Briefcase,
  Activity,
  Satellite,
  Link as LinkIcon,
  Unplug,
  FileCode,
  Lock,
  Calculator
} from 'lucide-react';

type ViewID = 'topology' | 'shell' | 'apt' | 'vuln' | 'pivot' | 'capabilities' | 'factory' | 'loot' | 'egress' | 'spectrum' | 'autonomous' | 'sigint' | 'satellite' | 'team' | 'firmware' | 'crypto' | 'exploit' | 'linkbudget';

const App: React.FC = () => {
  const c2 = useC2();
  const [activeView, setActiveView] = useState<ViewID>('topology');
  const [bridgeConnected, setBridgeConnected] = useState<boolean | null>(null);
  const terminalRef = useRef<TerminalHandle>(null);

  // Tactical Bridge Heartbeat Monitor
  useEffect(() => {
    const checkBridge = async () => {
      try {
        const resp = await fetch('http://localhost:8000/health', { method: 'GET' });
        setBridgeConnected(resp.ok);
      } catch (e) {
        setBridgeConnected(false);
      }
    };
    
    checkBridge();
    const interval = setInterval(checkBridge, 10000);
    return () => clearInterval(interval);
  }, []);

  if (c2.securityConfig.isAuthEnabled && !c2.currentOperator) {
    return <LoginScreen onLogin={c2.login} />;
  }

  const activeConnection = c2.connections.find(c => c.id === c2.activeConnectionId) || null;

  const handleCommandExecution = async (cmd: string, context: ShellContext): Promise<string> => {
    const targetId = context === 'local' ? 'localhost' : (c2.activeConnectionId || 'global');
    const taskId = c2.createTask(targetId, cmd);
    
    try {
      const result = await executeCommand(cmd, activeConnection, context);
      c2.updateTask(taskId, { status: 'completed', output: result.output });
      return result.output;
    } catch (err) {
      c2.updateTask(taskId, { status: 'failed' });
      return "Critical bridge failure: Signal lost.";
    }
  };

  const navGroups = [
    {
      name: 'Access',
      items: [
        { id: 'topology', icon: <Share2 size={14} />, label: 'Nexus' },
        { id: 'shell', icon: <TerminalIcon size={14} />, label: 'WinRM Shell' },
      ]
    },
    {
      name: 'Offensive',
      items: [
        { id: 'apt', icon: <Target size={14} />, label: 'APT' },
        { id: 'vuln', icon: <ShieldAlert size={14} />, label: 'Vuln' },
        { id: 'capabilities', icon: <Briefcase size={14} />, label: 'Modules' },
      ]
    },
    {
      name: 'Infra',
      items: [
        { id: 'pivot', icon: <Network size={14} />, label: 'Pivot' },
        { id: 'factory', icon: <Binary size={14} />, label: 'Foundry' },
        { id: 'egress', icon: <Globe size={14} />, label: 'Anonymity' },
        { id: 'spectrum', icon: <Wifi size={14} />, label: 'Mimicry' },
      ]
    },
    {
      name: 'Intel',
      items: [
        { id: 'loot', icon: <Database size={14} />, label: 'Vault' },
        { id: 'satellite', icon: <Satellite size={14} />, label: 'Orbital' },
        { id: 'sigint', icon: <Activity size={14} />, label: 'SIGINT' },
        { id: 'autonomous', icon: <Ghost size={14} />, label: 'Overlord' },
        { id: 'team', icon: <Settings size={14} />, label: 'Control' }
      ]
    },
    {
      name: 'SatEx',
      items: [
        { id: 'exploit', icon: <Target size={14} />, label: 'Exploit' },
        { id: 'firmware', icon: <FileCode size={14} />, label: 'Firmware' },
        { id: 'crypto', icon: <Lock size={14} />, label: 'Crypto' },
        { id: 'linkbudget', icon: <Calculator size={14} />, label: 'Link' }
      ]
    }
  ];

  return (
    <div className="flex h-screen w-full bg-[#020617] text-slate-100 overflow-hidden font-sans">
      <ConnectionSidebar 
        connections={c2.connections}
        activeId={c2.activeConnectionId}
        onConnect={c2.addConnection}
        onSelect={(id) => { c2.setActiveConnectionId(id); setActiveView('shell'); }}
        onDelete={c2.removeConnection}
      />

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-24 bg-[#0b1120] border-b border-white/5 flex items-center justify-between px-8 z-20 shadow-2xl relative">
          <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-emerald-500/50 to-transparent"></div>
          
          <nav className="flex items-center gap-6 h-full overflow-x-auto scrollbar-hide pr-4">
            {navGroups.map((group) => (
              <div key={group.name} className="flex items-center h-full">
                <div className="flex flex-col items-center justify-center mr-2 border-r border-white/5 pr-4 h-12">
                   <span className="text-[7px] font-black text-slate-600 uppercase tracking-widest leading-none mb-1">{group.name}</span>
                   <div className="w-1 h-1 rounded-full bg-slate-800"></div>
                </div>
                <div className="flex items-center gap-1 h-full">
                  {group.items.map((item) => (
                    <button 
                      key={item.id}
                      onClick={() => setActiveView(item.id as ViewID)}
                      className={`flex items-center gap-2 text-[9px] font-black uppercase tracking-[0.15em] transition-all px-4 h-full border-b-2 relative group whitespace-nowrap ${
                        activeView === item.id 
                          ? 'text-emerald-400 border-emerald-400 bg-emerald-400/5' 
                          : 'text-slate-500 border-transparent hover:text-slate-300'
                      }`}
                    >
                      {item.icon} {item.label}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </nav>

          <div className="flex items-center gap-6 shrink-0">
            {/* Tactical Bridge HUD Indicator */}
            <div className="flex flex-col items-end">
               <span className="text-[8px] font-black text-slate-500 uppercase tracking-widest">Tactical Bridge</span>
               <div className={`flex items-center gap-2 px-3 py-1 rounded-lg border transition-all ${
                 bridgeConnected === true ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-500' :
                 bridgeConnected === false ? 'bg-red-500/10 border-red-500/30 text-red-500 animate-pulse' :
                 'bg-slate-800 border-white/5 text-slate-600'
               }`}>
                  {bridgeConnected === true ? <LinkIcon size={12} /> : <Unplug size={12} />}
                  <span className="text-[10px] font-black uppercase tracking-widest">
                    {bridgeConnected === true ? 'ONLINE' : bridgeConnected === false ? 'OFFLINE' : 'SYNCING...'}
                  </span>
               </div>
            </div>

            <div className="hidden xl:flex flex-col items-end">
               <span className="text-[8px] font-black text-slate-500 uppercase tracking-widest">System Entropy</span>
               <div className="flex items-center gap-3">
                  <span className="text-sm font-black text-emerald-500">12.4%</span>
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]"></div>
               </div>
            </div>
            
            <div className="flex items-center gap-4 border-l border-white/5 pl-6">
              <div className="flex flex-col items-end">
                <span className="text-[8px] font-black text-slate-500 uppercase tracking-widest">Operator</span>
                <span className="text-[10px] font-black text-white uppercase">{c2.currentOperator?.alias || 'Master'}</span>
              </div>
              <button onClick={c2.logout} className="p-2.5 bg-slate-800 rounded-xl text-slate-400 hover:text-red-400 border border-white/5 transition-all shadow-inner active:scale-95">
                <LogOut size={14} />
              </button>
            </div>
          </div>
        </header>

        <main className="flex-1 p-8 xl:p-12 overflow-hidden relative">
          <div className="absolute inset-0 bg-[#020617]" style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, rgba(16,185,129,0.03) 2px, transparent 0)', backgroundSize: '48px 48px' }}></div>
          
          <div className="relative h-full z-10">
            {activeView === 'topology' && <NeuralEngagementMap connections={c2.connections} tasks={c2.tasks} onSelectTarget={c2.setActiveConnectionId} />}
            {activeView === 'apt' && <APTOrchestrator onExecuteChain={(chain) => console.log('Executing', chain.name)} />}
            {activeView === 'shell' && <Terminal ref={terminalRef} connection={activeConnection} onCommand={handleCommandExecution} />}
            {activeView === 'vuln' && <VulnerabilityValidator connections={c2.connections} onExecute={(ex, target) => console.log(`Exploiting ${target} with ${ex}`)} />}
            {activeView === 'pivot' && <PivotOrchestrator connections={c2.connections} />}
            {activeView === 'capabilities' && <ModuleBrowser activeConnection={activeConnection} onTaskModule={(cmd) => { if(terminalRef.current) { terminalRef.current.insertCommand(cmd); setActiveView('shell'); } }} />}
            {activeView === 'factory' && <PayloadFactory onInsertCode={(c) => { if(terminalRef.current) { terminalRef.current.insertCommand(c); setActiveView('shell'); } }} />}
            {activeView === 'loot' && <EvidenceVault />}
            {activeView === 'egress' && <TorEgressMonitor />}
            {activeView === 'spectrum' && <SpectrumStudio />}
            {activeView === 'autonomous' && <AutonomousOrchestrator connections={c2.connections} />}
            {activeView === 'sigint' && <OpSecMonitor connections={c2.connections} />}
            {activeView === 'satellite' && <SatelliteOrchestrator />}
            {activeView === 'team' && <OperatorSettings operators={c2.operators} config={c2.securityConfig} onUpdateConfig={(updates) => c2.setSecurityConfig(prev => ({ ...prev, ...updates }))} onRemoveOperator={() => {}} />}
            {activeView === 'exploit' && <SatelliteExploitOrchestrator />}
            {activeView === 'firmware' && <FirmwareStudio />}
            {activeView === 'crypto' && <CryptanalysisLab />}
            {activeView === 'linkbudget' && <LinkBudgetCalculator />}
          </div>
        </main>
      </div>

      <LabAssistant onInsertCode={(c) => { if(terminalRef.current) { terminalRef.current.insertCommand(c); setActiveView('shell'); } }} />
    </div>
  );
};

export default App;
