
import React, { useState } from 'react';
import { LootItem } from '../types';
import { Database, Key, ShieldCheck, FileText, Camera, Search, Filter, Download, MoreVertical } from 'lucide-react';

const MOCK_LOOT: LootItem[] = [
  // Fixed: Added capturedBy to satisfy LootItem interface
  { id: 'l1', type: 'hash', targetId: 't1', content: 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::', metadata: { host: 'DC01' }, timestamp: new Date(), verified: true, capturedBy: 'Spectre-Lead' },
  { id: 'l2', type: 'credential', targetId: 't2', content: 'svc_backup : BackupP@ss123!', metadata: { source: 'lsass.exe' }, timestamp: new Date(), verified: true, capturedBy: 'Spectre-Lead' },
  { id: 'l3', type: 'screenshot', targetId: 't1', content: 'https://images.unsplash.com/photo-1550751827-4bd374c3f58b', metadata: { resolution: '1920x1080' }, timestamp: new Date(), verified: false, capturedBy: 'Spectre-Lead' }
];

const LootVault: React.FC = () => {
  const [filter, setFilter] = useState<'all' | LootItem['type']>('all');

  return (
    <div className="h-full flex flex-col gap-6 animate-in fade-in duration-500">
      <header className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
            <Database size={20} /> Loot Vault & Evidence
          </h2>
          <p className="text-[10px] text-slate-500 uppercase tracking-widest font-bold mt-1">Structured Exfiltration & Verification</p>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-[10px] font-black uppercase flex items-center gap-2">
            <Download size={14} /> Export Report
          </button>
        </div>
      </header>

      <div className="bg-slate-900/50 border border-slate-800 rounded-3xl overflow-hidden flex flex-col">
        <div className="p-4 border-b border-white/5 flex gap-4 items-center bg-black/20">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input placeholder="Search vault contents..." className="w-full bg-black/40 border border-white/5 rounded-lg py-2 pl-9 pr-4 text-[10px] font-mono outline-none focus:border-emerald-500 transition-all" />
          </div>
          <div className="flex bg-black/40 rounded-lg p-1 border border-white/5">
            {(['all', 'hash', 'credential', 'screenshot'] as const).map(f => (
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
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Item</th>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Target</th>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Content Preview</th>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Captured</th>
                <th className="p-4 text-[10px] font-black text-slate-500 uppercase">Status</th>
                <th className="p-4 w-10"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {MOCK_LOOT.filter(l => filter === 'all' || l.type === filter).map(item => (
                <tr key={item.id} className="hover:bg-white/[0.02] group transition-colors">
                  <td className="p-4">
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg bg-black/40 border border-white/5 ${
                        item.type === 'hash' ? 'text-purple-400' : 
                        item.type === 'credential' ? 'text-blue-400' : 'text-yellow-400'
                      }`}>
                        {item.type === 'hash' ? <Key size={14} /> : 
                         item.type === 'credential' ? <ShieldCheck size={14} /> : <Camera size={14} />}
                      </div>
                      <span className="text-[10px] font-black text-slate-300 uppercase">{item.type}</span>
                    </div>
                  </td>
                  <td className="p-4 font-mono text-[10px] text-slate-500">
                    {item.metadata.host || item.targetId}
                  </td>
                  <td className="p-4">
                    <div className="max-w-xs truncate font-mono text-[10px] text-slate-400 bg-black/20 p-2 rounded-md">
                      {item.content}
                    </div>
                  </td>
                  <td className="p-4 text-[10px] text-slate-600">
                    {item.timestamp.toLocaleTimeString()}
                  </td>
                  <td className="p-4">
                    {item.verified ? (
                      <span className="text-[8px] font-black text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">VERIFIED</span>
                    ) : (
                      <span className="text-[8px] font-black text-slate-500 bg-slate-500/10 px-2 py-0.5 rounded border border-slate-500/20">STAGED</span>
                    )}
                  </td>
                  <td className="p-4">
                    <button className="text-slate-700 hover:text-white transition-colors opacity-0 group-hover:opacity-100">
                      <MoreVertical size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          
          {MOCK_LOOT.length === 0 && (
            <div className="py-20 flex flex-col items-center justify-center text-slate-600 opacity-20 italic">
              <Database size={48} className="mb-4" />
              <p className="text-xs font-black uppercase tracking-widest">Vault is empty. Run automated loot macros.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default LootVault;
