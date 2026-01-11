import React, { useState } from 'react';
import { Terminal, Search, AlertTriangle, Copy, Play, BookOpen } from 'lucide-react';
import { CommandTemplate } from '../types';
import { COMMAND_TEMPLATES } from '../data/commandTemplates';

interface CommandTemplateLibraryProps {
  onExecute: (command: string) => void;
}

const CommandTemplateLibrary: React.FC<CommandTemplateLibraryProps> = ({ onExecute }) => {
  const [search, setSearch] = useState('');
  const [selectedTemplate, setSelectedTemplate] = useState<CommandTemplate | null>(null);
  const [params, setParams] = useState<Record<string, string>>({});
  const [category, setCategory] = useState<string>('all');

  const categories = ['all', ...Array.from(new Set(COMMAND_TEMPLATES.map(t => t.category)))];
  
  const filtered = COMMAND_TEMPLATES.filter(template => {
    const matchesSearch = template.name.toLowerCase().includes(search.toLowerCase()) ||
                         template.description.toLowerCase().includes(search.toLowerCase());
    const matchesCategory = category === 'all' || template.category === category;
    return matchesSearch && matchesCategory;
  });

  const buildCommand = (template: CommandTemplate): string => {
    let cmd = template.template;
    Object.entries(params).forEach(([key, value]) => {
      if (value) {
        cmd = cmd.replace(`{${key}}`, value);
      }
    });
    return cmd;
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'low': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  return (
    <div className="h-full flex flex-col gap-6">
      <header>
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <Terminal size={20} /> Command Template Library
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">
          Pre-Built Satellite Operations Commands
        </p>
      </header>

      <div className="flex gap-4">
        <div className="relative flex-1">
          <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" />
          <input
            type="text"
            placeholder="Search commands..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-black/40 border border-slate-800 rounded-2xl pl-12 pr-4 py-3 text-sm text-slate-400 outline-none focus:border-emerald-500 transition-all"
          />
        </div>
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="bg-black/40 border border-slate-800 rounded-2xl px-4 py-3 text-sm text-slate-400 outline-none focus:border-emerald-500 transition-all"
        >
          {categories.map(cat => (
            <option key={cat} value={cat}>
              {cat.replace('_', ' ').toUpperCase()}
            </option>
          ))}
        </select>
      </div>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 overflow-hidden">
        <div className="lg:col-span-5 flex flex-col gap-4 overflow-y-auto pr-2">
          {filtered.map(template => (
            <button
              key={template.id}
              onClick={() => {
                setSelectedTemplate(template);
                const defaultParams: Record<string, string> = {};
                Object.entries(template.params).forEach(([key, param]) => {
                  if (param.default !== undefined) {
                    defaultParams[key] = String(param.default);
                  }
                });
                setParams(defaultParams);
              }}
              className={`text-left p-4 rounded-2xl border transition-all ${
                selectedTemplate?.id === template.id
                  ? 'bg-emerald-500/10 border-emerald-500/30'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="font-bold text-sm text-slate-300">{template.name}</div>
                <div className={`text-[10px] font-black uppercase px-2 py-1 rounded-lg border ${getRiskColor(template.risk)}`}>
                  {template.risk}
                </div>
              </div>
              <div className="text-xs text-slate-500 mb-2">{template.description}</div>
              <div className="flex items-center gap-2 text-[10px] text-slate-600 uppercase font-bold">
                <BookOpen size={10} />
                {template.category.replace('_', ' ')}
              </div>
            </button>
          ))}

          {filtered.length === 0 && (
            <div className="text-center py-12 text-slate-600">
              <Terminal size={40} className="mx-auto mb-3 opacity-30" />
              <div className="text-sm font-bold uppercase">No Commands Found</div>
            </div>
          )}
        </div>

        <div className="lg:col-span-7 flex flex-col gap-4">
          {selectedTemplate ? (
            <>
              <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-lg font-black text-emerald-400">{selectedTemplate.name}</h3>
                    <p className="text-xs text-slate-500 mt-1">{selectedTemplate.description}</p>
                  </div>
                  <div className={`text-xs font-black uppercase px-3 py-1.5 rounded-lg border ${getRiskColor(selectedTemplate.risk)}`}>
                    {selectedTemplate.risk} Risk
                  </div>
                </div>

                {selectedTemplate.risk !== 'low' && (
                  <div className={`flex items-start gap-2 p-3 rounded-xl border ${
                    selectedTemplate.risk === 'critical' ? 'bg-red-500/5 border-red-500/30' : 'bg-yellow-500/5 border-yellow-500/30'
                  }`}>
                    <AlertTriangle size={16} className={selectedTemplate.risk === 'critical' ? 'text-red-500' : 'text-yellow-500'} />
                    <div className="text-xs text-slate-400">
                      This command has {selectedTemplate.risk} risk level. Ensure proper authorization before execution.
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  <div className="text-xs font-black uppercase text-slate-600">Requirements</div>
                  <div className="flex flex-wrap gap-2">
                    {selectedTemplate.requirements.map((req, idx) => (
                      <div key={idx} className="text-xs px-2 py-1 bg-blue-500/10 text-blue-400 rounded-lg border border-blue-500/30">
                        {req}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="text-xs font-black uppercase text-slate-600">Parameters</div>
                  {Object.entries(selectedTemplate.params).map(([key, param]) => (
                    <div key={key} className="space-y-1">
                      <label className="text-xs font-bold text-slate-400 flex items-center gap-2">
                        {key}
                        {param.required && <span className="text-red-500">*</span>}
                        {!param.required && <span className="text-slate-600">(optional)</span>}
                      </label>
                      <input
                        type={param.type === 'number' ? 'number' : 'text'}
                        placeholder={param.description}
                        value={params[key] || ''}
                        onChange={(e) => setParams({ ...params, [key]: e.target.value })}
                        className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm font-mono text-slate-300 outline-none focus:border-emerald-500 transition-all"
                      />
                      <div className="text-[10px] text-slate-600">{param.description}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-black border border-slate-800 rounded-2xl p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-black uppercase text-slate-600">Generated Command</div>
                  <button
                    onClick={() => navigator.clipboard.writeText(buildCommand(selectedTemplate))}
                    className="text-xs flex items-center gap-1 text-slate-500 hover:text-emerald-400 transition-colors"
                  >
                    <Copy size={12} />
                    Copy
                  </button>
                </div>
                <pre className="text-xs font-mono text-emerald-400 whitespace-pre-wrap break-all">
                  {buildCommand(selectedTemplate)}
                </pre>
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => navigator.clipboard.writeText(buildCommand(selectedTemplate))}
                  className="flex-1 py-3 bg-slate-800 hover:bg-slate-700 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
                >
                  <Copy size={16} />
                  Copy to Clipboard
                </button>
                <button
                  onClick={() => onExecute(buildCommand(selectedTemplate))}
                  className="flex-1 py-3 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
                >
                  <Play size={16} />
                  Execute Command
                </button>
              </div>

              <div className="bg-blue-500/5 border border-blue-500/30 rounded-xl p-3 text-xs text-blue-400">
                <div className="font-bold mb-1">Example Usage:</div>
                <code className="text-slate-400">{selectedTemplate.example}</code>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-center text-slate-600">
              <div>
                <Terminal size={60} className="mx-auto mb-4 opacity-20" />
                <div className="font-bold uppercase">Select a Command Template</div>
                <div className="text-xs mt-2">Choose from the list to view parameters and build your command</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CommandTemplateLibrary;
