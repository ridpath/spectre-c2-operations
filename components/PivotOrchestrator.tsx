
import React, { useState } from 'react';
import { useLigolo } from '../hooks/useLigolo';
import { WinRMConnection } from '../types';
import { Network, Power, Plus, Route, Activity, Server, Zap, Globe, ShieldCheck } from 'lucide-react';

interface PivotOrchestratorProps {
  connections: WinRMConnection[];
}

const PivotOrchestrator: React.FC<PivotOrchestratorProps> = ({ connections }) => {
  const tunnelService = useLigolo();
  const [selectedAgentId, setSelectedAgentId] = useState('');

  const handleStartTunnel = () => {
    const agent = connections.find(c => c.id === selectedAgentId);
    if (agent) {
      tunnelService.createTunnel(agent.id, agent.host);
    }
  };

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-500">
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-blue-400 uppercase tracking-tighter flex items-center gap-2">
            <Network size={20} /> Network Pivoting & Tunneling
          </h2>
          <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">Transparent TUN Interface Management</p>
        </div>
        <button 
          onClick={tunnelService.isRelayStarted ? tunnelService.stopRelay : tunnelService.startRelay}
          className={`px-6 py-2 rounded-full text-[10px] font-black uppercase transition-all flex items-center gap-2 shadow-xl ${
            tunnelService.isRelayStarted 
              ? 'bg-red-600/20 text-red-400 border border-red-500/30' 
              : 'bg-emerald-600 text-white shadow-emerald-900/20'
          }`}
        >
          <Power size={14} />
          {tunnelService.isRelayStarted ? 'Deactivate Relay' : 'Activate Network Relay'}
        </button>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 overflow-hidden">
        <div className="lg:col-span-8 space-y-4 overflow-y-auto pr-2">
          {tunnelService.tunnels.map(tun => (
            <div key={tun.id} className="bg-slate-900/40 border border-slate-800 rounded-3xl p-6 relative overflow-hidden group hover:border-blue-500/30 transition-all">
              <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10">
                <Globe size={64} />
              </div>
              
              <div className="flex justify-between items-start mb-6">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-blue-500/10 border border-blue-500/20 rounded-2xl flex items-center justify-center text-blue-400">
                    <Activity size={24} />
                  </div>
                  <div>
                    <h3 className="text-sm font-black text-slate-100 uppercase">{tun.interfaceName}</h3>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-[9px] font-black text-emerald-500 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">ACTIVE</span>
                      <span className="text-[9px] font-mono text-slate-500">PEER: {tun.remoteAddress}</span>
                    </div>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4 text-right">
                  <div>
                    <div className="text-[8px] font-black text-slate-600 uppercase">RX Bytes</div>
                    <div className="text-[10px] font-mono text-blue-400">{(tun.rxBytes / 1024).toFixed(2)} KB</div>
                  </div>
                  <div>
                    <div className="text-[8px] font-black text-slate-600 uppercase">TX Bytes</div>
                    <div className="text-[10px] font-mono text-emerald-400">{(tun.txBytes / 1024).toFixed(2)} KB</div>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center justify-between text-[9px] font-black text-slate-500 uppercase tracking-widest border-b border-white/5 pb-2">
                  <span>Routing Table</span>
                  <Route size={12} />
                </div>
                <div className="flex flex-wrap gap-2">
                  {tun.routes.map((r, i) => (
                    <div key={i} className="px-3 py-1 bg-black/40 border border-slate-800 rounded-lg text-[10px] font-mono text-slate-300 flex items-center gap-2">
                      <Zap size={10} className="text-yellow-500" />
                      {r}
                    </div>
                  ))}
                  <div className="flex gap-2 flex-1">
                    <input 
                      placeholder="Inject Route (e.g. 172.16.1.0/24)" 
                      className="bg-black/60 border border-white/5 rounded-lg px-3 py-1 text-[10px] font-mono flex-1 outline-none focus:border-blue-500 transition-all"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          tunnelService.addRoute(tun.id, e.currentTarget.value);
                          e.currentTarget.value = '';
                        }
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>
          ))}

          {tunnelService.tunnels.length === 0 && (
            <div className="h-64 border-2 border-dashed border-slate-800 rounded-3xl flex flex-col items-center justify-center opacity-30 grayscale italic">
              <Network size={48} className="mb-4" />
              <p className="text-xs font-black uppercase tracking-widest">No Active Tunnels</p>
            </div>
          )}
        </div>

        <div className="lg:col-span-4 space-y-6">
          <section className="bg-slate-900/60 border border-slate-800 rounded-3xl p-6 space-y-6 shadow-2xl">
            <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] flex items-center gap-2">
              <Plus size={14} className="text-blue-500" /> Establish Link
            </h3>
            
            <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-[9px] font-black text-slate-600 uppercase">Available Beacons</label>
                <select 
                  value={selectedAgentId}
                  onChange={e => setSelectedAgentId(e.target.value)}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl p-3 text-xs text-slate-300 outline-none focus:border-blue-500"
                >
                  <option value="">Select Target...</option>
                  {connections.map(c => (
                    <option key={c.id} value={c.id}>{c.host} ({c.username})</option>
                  ))}
                </select>
              </div>

              <div className="p-4 bg-blue-500/5 border border-blue-500/20 rounded-2xl flex items-start gap-3">
                <ShieldCheck size={18} className="text-blue-400 mt-1 shrink-0" />
                <p className="text-[9px] text-slate-400 leading-relaxed italic">
                  Selecting a target will request a remote reverse-connection to the relay service on port 11601.
                </p>
              </div>

              <button 
                disabled={!selectedAgentId || !tunnelService.isRelayStarted}
                onClick={handleStartTunnel}
                className="w-full py-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-20 disabled:grayscale text-white rounded-2xl text-xs font-black transition-all flex items-center justify-center gap-2 shadow-xl shadow-blue-900/30 group"
              >
                <Server size={18} className="group-hover:translate-y-[-2px] transition-transform" />
                Spawn TUN Interface
              </button>
            </div>
          </section>

          <section className="bg-black/40 border border-white/5 rounded-3xl p-6 space-y-4">
            <h3 className="text-[10px] font-black text-slate-600 uppercase tracking-widest flex items-center gap-2">
              <Activity size={14} /> Interface Metrics
            </h3>
            <div className="space-y-2">
              <div className="flex justify-between text-[10px] font-mono">
                <span className="text-slate-500">Relay Status:</span>
                <span className={tunnelService.isRelayStarted ? 'text-emerald-500' : 'text-red-500'}>
                  {tunnelService.isRelayStarted ? 'READY' : 'INACTIVE'}
                </span>
              </div>
              <div className="flex justify-between text-[10px] font-mono">
                <span className="text-slate-500">Active Bridges:</span>
                <span className="text-blue-400">{tunnelService.tunnels.length}</span>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default PivotOrchestrator;
