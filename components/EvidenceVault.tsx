
import React, { useState, useEffect } from 'react';
import { Database, Key, ShieldCheck, Camera, Search, Download, MoreVertical, HardDrive, Waves, Terminal, Bug } from 'lucide-react';
import { evidenceService, Evidence } from '../services/evidenceService';
import { demoModeService } from '../services/demoModeService';

const MOCK_LOOT = [
  { id: 'l1', category: 'hash', mission_id: 't1', data: 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::', metadata: { host: 'DC01' }, timestamp: new Date().toISOString(), description: 'NTLM Hash Captured', tags: ['credentials'] },
  { id: 'l2', category: 'credential', mission_id: 't2', data: 'svc_backup : BackupP@ss123!', metadata: { source: 'lsass.exe' }, timestamp: new Date().toISOString(), description: 'Service Account Password', tags: ['credentials'] },
  { id: 'l3', category: 'screenshot', mission_id: 't1', file_path: 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b', metadata: { resolution: '1920x1080' }, timestamp: new Date().toISOString(), description: 'Desktop Screenshot', tags: ['visual'] },
  { id: 'l4', category: 'iq', mission_id: 'sat-leo-01', data: 'iq_capture_20240520_1422.raw', metadata: { size: '1.2 GB', freq: '2.2 GHz', samp_rate: '2.0 MS/s' }, timestamp: new Date().toISOString(), description: 'IQ Recording Captured', satellite_name: 'LEO-SAT-01', frequency: 2200000000 }
];

const EvidenceVault: React.FC = () => {
  const [filter, setFilter] = useState<'all' | Evidence['category']>('all');
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [loading, setLoading] = useState(true);
  const [isDemo, setIsDemo] = useState(false);

  useEffect(() => {
    const unsubscribe = demoModeService.subscribe(setIsDemo);
    return unsubscribe;
  }, []);

  useEffect(() => {
    loadEvidence();
  }, [isDemo]);

  const loadEvidence = async () => {
    setLoading(true);
    if (isDemo) {
      setEvidence(MOCK_LOOT as any);
    } else {
      const data = await evidenceService.getEvidence();
      setEvidence(data);
    }
    setLoading(false);
  };

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-500">
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
            <Database size={20} /> Tactical Evidence Vault
          </h2>
          <p className="text-[10px] text-slate-500 uppercase tracking-widest font-black mt-1">Structured Exfiltration & Asset Verification</p>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-[10px] font-black uppercase flex items-center gap-2 transition-all">
            <Download size={14} /> Export Findings
          </button>
        </div>
      </header>

      <div className="bg-slate-900/50 border border-slate-800 rounded-3xl overflow-hidden flex flex-col shadow-2xl">
        <div className="p-4 border-b border-white/5 flex gap-4 items-center bg-black/20 overflow-x-auto scrollbar-hide">
          <div className="relative flex-1 min-w-[200px]">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input placeholder="Search captured strings..." className="w-full bg-black/40 border border-white/5 rounded-lg py-2 pl-9 pr-4 text-[10px] font-mono outline-none focus:border-emerald-500 transition-all" />
          </div>
          <div className="flex bg-black/40 rounded-lg p-1 border border-white/5 shrink-0">
            {(['all', 'hash', 'credential', 'screenshot', 'iq', 'file', 'module_execution', 'exploit'] as const).map(f => (
              <button 
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1.5 rounded-md text-[9px] font-black uppercase transition-all ${
                  filter === f ? 'bg-emerald-600 text-white shadow-lg' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          <table className="w-full text-left border-collapse">
            <thead className="bg-black/40 sticky top-0 z-10">
              <tr>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Discovery</th>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Origin</th>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Data Summary</th>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Timestamp</th>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Verification</th>
                <th className="p-4 w-10"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {loading ? (
                <tr><td colSpan={6} className="p-8 text-center text-slate-500 text-xs">Loading evidence...</td></tr>
              ) : evidence.filter(e => filter === 'all' || e.category === filter).length === 0 ? (
                <tr><td colSpan={6} className="p-8 text-center text-slate-500 text-xs">No evidence collected yet. Execute modules to capture evidence.</td></tr>
              ) : (
                evidence.filter(e => filter === 'all' || e.category === filter).map(item => {
                  const getIcon = () => {
                    switch(item.category) {
                      case 'hash': return <Key size={14} />;
                      case 'credential': return <ShieldCheck size={14} />;
                      case 'iq': return <Waves size={14} />;
                      case 'screenshot': return <Camera size={14} />;
                      case 'file': return <HardDrive size={14} />;
                      case 'module_execution': return <Terminal size={14} />;
                      case 'exploit': return <Bug size={14} />;
                      default: return <Database size={14} />;
                    }
                  };

                  const getColor = () => {
                    switch(item.category) {
                      case 'hash': return 'text-purple-400';
                      case 'credential': return 'text-blue-400';
                      case 'iq': return 'text-emerald-400';
                      case 'screenshot': return 'text-yellow-400';
                      case 'file': return 'text-cyan-400';
                      case 'module_execution': return 'text-orange-400';
                      case 'exploit': return 'text-red-400';
                      default: return 'text-slate-400';
                    }
                  };

                  return (
                    <tr key={item.id} className="hover:bg-white/[0.02] group transition-colors">
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-lg bg-black/40 border border-white/5 ${getColor()}`}>
                            {getIcon()}
                          </div>
                          <span className="text-[10px] font-black text-slate-300 uppercase">{item.category}</span>
                        </div>
                      </td>
                      <td className="p-4 font-mono text-[10px] text-slate-500 uppercase tracking-tighter">
                        {item.metadata?.host || item.satellite_name || item.metadata?.freq || item.mission_id}
                      </td>
                      <td className="p-4">
                        <div className="max-w-xs truncate font-mono text-[10px] text-slate-400 bg-black/20 p-2 rounded-md border border-white/5">
                          {item.category === 'iq' && item.metadata?.size 
                            ? `${item.data} (${item.metadata.size})` 
                            : item.data || item.description}
                        </div>
                      </td>
                      <td className="p-4 text-[10px] text-slate-600">
                        {new Date(item.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="p-4">
                        {item.tags?.includes('verified') || item.metadata?.verified ? (
                          <span className="text-[8px] font-black text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">VALIDATED</span>
                        ) : (
                          <span className="text-[8px] font-black text-slate-500 bg-slate-500/10 px-2 py-0.5 rounded border border-slate-500/20">UNVERIFIED</span>
                        )}
                      </td>
                  <td className="p-4">
                    <button className="text-slate-700 hover:text-white transition-colors opacity-0 group-hover:opacity-100">
                      <MoreVertical size={14} />
                    </button>
                  </td>
                </tr>
                );
              })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default EvidenceVault;
