
import React from 'react';
import { Operator, SecurityConfig } from '../types';
import { Users, Shield, Key, Power, Trash2, Clock, CheckCircle2, AlertTriangle } from 'lucide-react';

interface OperatorSettingsProps {
  operators: Operator[];
  config: SecurityConfig;
  onUpdateConfig: (updates: Partial<SecurityConfig>) => void;
  onRemoveOperator: (id: string) => void;
}

const OperatorSettings: React.FC<OperatorSettingsProps> = ({ operators, config, onUpdateConfig, onRemoveOperator }) => {
  return (
    <div className="h-full flex flex-col gap-8 animate-in fade-in duration-500">
      <header>
        <h2 className="text-xl font-black text-white uppercase tracking-tighter flex items-center gap-3">
          <Users size={20} className="text-blue-500" /> Operator Control Center
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-black tracking-widest mt-1">Multi-User Authentication & Permission Logic</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 overflow-hidden">
        {/* Security Configuration */}
        <div className="lg:col-span-4 space-y-6">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2rem] p-8 space-y-8">
            <h3 className="text-xs font-black text-slate-400 uppercase tracking-widest flex items-center gap-2">
              <Shield size={16} className="text-emerald-500" /> Global Security Mode
            </h3>

            <div className="space-y-6">
               <div className="flex items-center justify-between p-4 bg-black/40 rounded-2xl border border-white/5">
                  <div>
                    <div className="text-[10px] font-black text-slate-200 uppercase tracking-tight">Operator Authentication</div>
                    <div className="text-[8px] text-slate-600 mt-0.5">Force secure login for all operators</div>
                  </div>
                  <button 
                    onClick={() => onUpdateConfig({ isAuthEnabled: !config.isAuthEnabled })}
                    className={`w-12 h-6 rounded-full transition-all relative ${config.isAuthEnabled ? 'bg-emerald-600' : 'bg-slate-800'}`}
                  >
                    <div className={`absolute top-1 w-4 h-4 rounded-full bg-white transition-all ${config.isAuthEnabled ? 'left-7' : 'left-1'}`}></div>
                  </button>
               </div>

               <div className="flex items-center justify-between p-4 bg-black/40 rounded-2xl border border-white/5 opacity-50">
                  <div>
                    <div className="text-[10px] font-black text-slate-200 uppercase tracking-tight">Two-Factor Biometrics</div>
                    <div className="text-[8px] text-slate-600 mt-0.5">Enable PGP-signed handshake tokens</div>
                  </div>
                  <button className="w-12 h-6 rounded-full bg-slate-800 relative cursor-not-allowed">
                    <div className="absolute top-1 left-1 w-4 h-4 rounded-full bg-slate-600"></div>
                  </button>
               </div>
            </div>

            <div className="p-4 bg-blue-500/5 border border-blue-500/20 rounded-2xl">
               <div className="flex items-start gap-3">
                  <AlertTriangle size={16} className="text-blue-400 mt-0.5" />
                  <p className="text-[9px] text-blue-400/80 leading-relaxed italic">
                    "When Authentication is disabled, any client reaching the Core Signal Port will be automatically granted Master Administrator privileges."
                  </p>
               </div>
            </div>
          </section>
        </div>

        {/* Active Operators List */}
        <div className="lg:col-span-8 flex flex-col gap-6">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] flex-1 overflow-hidden flex flex-col">
            <div className="px-8 py-6 border-b border-white/5 bg-black/20 flex justify-between items-center">
               <h3 className="text-xs font-black text-slate-300 uppercase tracking-widest flex items-center gap-2">
                  <Key size={16} className="text-blue-500" /> Authorized Personnel
               </h3>
               <span className="text-[10px] font-mono text-emerald-500/50">{operators.length} Active Sessions</span>
            </div>

            <div className="flex-1 overflow-y-auto">
               <table className="w-full text-left">
                  <thead className="text-[10px] font-black text-slate-600 uppercase tracking-widest">
                     <tr className="border-b border-white/5">
                        <th className="px-8 py-4">Alias</th>
                        <th className="px-8 py-4">Role</th>
                        <th className="px-8 py-4">Last Telemetry</th>
                        <th className="px-8 py-4">Status</th>
                        <th className="px-8 py-4 text-right">Actions</th>
                     </tr>
                  </thead>
                  <tbody className="divide-y divide-white/5 text-[11px]">
                     {operators.map(op => (
                        <tr key={op.id} className="hover:bg-white/[0.02] group transition-colors">
                           <td className="px-8 py-5">
                              <div className="flex items-center gap-3">
                                 <div className="w-8 h-8 rounded-full bg-slate-800 flex items-center justify-center text-slate-400 border border-white/5">
                                    <Users size={14} />
                                 </div>
                                 <span className="font-black text-slate-200">{op.alias}</span>
                              </div>
                           </td>
                           <td className="px-8 py-5">
                              <span className={`text-[8px] font-black px-2 py-0.5 rounded border ${
                                 op.role === 'ADMIN' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                              }`}>
                                 {op.role}
                              </span>
                           </td>
                           <td className="px-8 py-5 text-slate-500 font-mono text-[10px]">
                              {op.lastSeen.toLocaleTimeString()}
                           </td>
                           <td className="px-8 py-5">
                              <div className="flex items-center gap-2">
                                 <div className={`w-1.5 h-1.5 rounded-full ${op.status === 'active' ? 'bg-emerald-500 animate-pulse shadow-[0_0_5px_#10b981]' : 'bg-slate-700'}`}></div>
                                 <span className={`text-[9px] font-black uppercase ${op.status === 'active' ? 'text-emerald-500' : 'text-slate-700'}`}>{op.status}</span>
                              </div>
                           </td>
                           <td className="px-8 py-5 text-right">
                              <button 
                                onClick={() => onRemoveOperator(op.id)}
                                className="p-2 text-slate-700 hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
                              >
                                 <Trash2 size={16} />
                              </button>
                           </td>
                        </tr>
                     ))}
                  </tbody>
               </table>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default OperatorSettings;
