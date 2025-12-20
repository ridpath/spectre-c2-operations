
import React, { useState } from 'react';
import { WinRMConnection, AuthMethod } from '../types';
import { Plus, Shield, Server, Activity, ChevronRight, X } from 'lucide-react';

interface SidebarProps {
  connections: WinRMConnection[];
  activeId: string | null;
  onConnect: (conn: Partial<WinRMConnection>) => void;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
}

const ConnectionSidebar: React.FC<SidebarProps> = ({ connections, activeId, onConnect, onSelect, onDelete }) => {
  const [isAdding, setIsAdding] = useState(false);
  const [newConn, setNewConn] = useState<Partial<WinRMConnection>>({
    host: '',
    username: '',
    password: '',
    port: 5985,
    useSsl: false,
    authMethod: AuthMethod.NTLM
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onConnect(newConn);
    setIsAdding(false);
    setNewConn({ host: '', username: '', password: '', port: 5985, useSsl: false, authMethod: AuthMethod.NTLM });
  };

  return (
    <div className="w-80 bg-[#1e293b] border-r border-slate-800 flex flex-col h-full">
      <div className="p-4 border-b border-slate-800 flex justify-between items-center">
        <div className="flex items-center gap-2">
          <div className="p-2 bg-emerald-600 rounded-lg shadow-lg shadow-emerald-900/20">
            <Shield size={18} className="text-white" />
          </div>
          <h1 className="font-black text-sm text-slate-100 uppercase tracking-tighter">Spectre C2</h1>
        </div>
        <button 
          onClick={() => setIsAdding(!isAdding)}
          className="p-1.5 hover:bg-slate-700 rounded-full text-slate-300 transition-colors"
        >
          {isAdding ? <X size={20} /> : <Plus size={20} />}
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {isAdding && (
          <form onSubmit={handleSubmit} className="p-4 bg-slate-800/50 border-b border-slate-700 space-y-3 animate-in slide-in-from-top-4 duration-200">
            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Host / IP</label>
              <input 
                required
                className="w-full bg-slate-900 border-slate-700 rounded p-2 text-sm text-slate-100"
                placeholder="10.10.11.23..."
                value={newConn.host}
                onChange={e => setNewConn({...newConn, host: e.target.value})}
              />
            </div>
            <div className="flex gap-2">
              <div className="flex-1 space-y-1">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">User</label>
                <input 
                  required
                  className="w-full bg-slate-900 border-slate-700 rounded p-2 text-sm text-slate-100"
                  placeholder="Administrator"
                  value={newConn.username}
                  onChange={e => setNewConn({...newConn, username: e.target.value})}
                />
              </div>
              <div className="flex-1 space-y-1">
                <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Auth</label>
                <select 
                  className="w-full bg-slate-900 border-slate-700 rounded p-2 text-sm text-slate-100"
                  value={newConn.authMethod}
                  onChange={e => setNewConn({...newConn, authMethod: e.target.value as AuthMethod})}
                >
                  {Object.values(AuthMethod).map(m => <option key={m} value={m}>{m}</option>)}
                </select>
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Password</label>
              <input 
                type="password"
                className="w-full bg-slate-900 border-slate-700 rounded p-2 text-sm text-slate-100"
                placeholder="••••••••"
                value={newConn.password}
                onChange={e => setNewConn({...newConn, password: e.target.value})}
              />
            </div>
            <button className="w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-sm font-bold shadow-lg transition-all">
              Establish Beacon
            </button>
          </form>
        )}

        <div className="p-2 space-y-1">
          <label className="px-3 py-2 text-[10px] font-black text-slate-500 uppercase tracking-widest">Active Assets</label>
          {connections.length === 0 && !isAdding && (
            <div className="px-3 py-8 text-center text-slate-600 space-y-2">
              <Server size={32} className="mx-auto opacity-20" />
              <p className="text-[10px] font-black uppercase tracking-widest">No Active Beacons</p>
            </div>
          )}
          {connections.map(conn => (
            <div 
              key={conn.id}
              onClick={() => onSelect(conn.id)}
              className={`group flex items-center justify-between p-3 rounded-xl cursor-pointer transition-all ${
                activeId === conn.id ? 'bg-emerald-600/10 border-l-4 border-emerald-500' : 'hover:bg-slate-800'
              }`}
            >
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${
                  conn.status === 'connected' ? 'bg-emerald-500/20 text-emerald-400' : 
                  conn.status === 'error' ? 'bg-red-500/20 text-red-400' : 'bg-slate-700 text-slate-400'
                }`}>
                  <Activity size={16} />
                </div>
                <div>
                  <div className="text-sm font-bold text-slate-100">{conn.host}</div>
                  <div className="text-[10px] text-slate-500 uppercase font-bold tracking-tighter">{conn.username} • {conn.authMethod}</div>
                </div>
              </div>
              <ChevronRight size={14} className={`text-slate-600 group-hover:text-slate-400 transition-colors ${activeId === conn.id ? 'text-emerald-400' : ''}`} />
            </div>
          ))}
        </div>
      </div>

      <div className="p-4 bg-slate-900/50 border-t border-slate-800">
        <div className="flex items-center gap-2 text-[10px] font-black text-slate-600 uppercase tracking-widest">
          <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_5px_#10b981]"></div>
          Signal Core Online
        </div>
      </div>
    </div>
  );
};

export default ConnectionSidebar;
