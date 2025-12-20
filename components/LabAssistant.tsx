
import React, { useState } from 'react';
import { Sparkles, Terminal as TerminalIcon, Search, List } from 'lucide-react';
import { suggestNextSteps } from '../services/geminiService';
import { DEFAULT_SNIPPETS } from '../constants';

interface LabAssistantProps {
  onInsertCode: (code: string) => void;
}

const LabAssistant: React.FC<LabAssistantProps> = ({ onInsertCode }) => {
  const [activeTab, setActiveTab] = useState<'snippets' | 'ai'>('snippets');
  const [aiSuggestions, setAiSuggestions] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);

  const fetchAiSuggestions = async () => {
    setIsLoading(true);
    const suggestion = await suggestNextSteps(['whoami', 'ipconfig', 'net user /domain']);
    setAiSuggestions(suggestion);
    setIsLoading(false);
  };

  return (
    <div className="w-80 bg-[#1e293b] border-l border-slate-800 flex flex-col h-full">
      <div className="flex border-b border-slate-800">
        <button 
          onClick={() => setActiveTab('snippets')}
          className={`flex-1 py-3 text-xs font-bold uppercase tracking-wider transition-colors ${
            activeTab === 'snippets' ? 'text-blue-400 border-b-2 border-blue-500' : 'text-slate-500 hover:text-slate-300'
          }`}
        >
          <div className="flex items-center justify-center gap-2">
            <List size={14} /> Snippets
          </div>
        </button>
        <button 
          onClick={() => setActiveTab('ai')}
          className={`flex-1 py-3 text-xs font-bold uppercase tracking-wider transition-colors ${
            activeTab === 'ai' ? 'text-emerald-400 border-b-2 border-emerald-500' : 'text-slate-500 hover:text-slate-300'
          }`}
        >
          <div className="flex items-center justify-center gap-2">
            <Sparkles size={14} /> Spectre Intel
          </div>
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === 'snippets' ? (
          <div className="space-y-4">
            {DEFAULT_SNIPPETS.map(snippet => (
              <div 
                key={snippet.id}
                className="p-3 rounded-xl border border-slate-700 bg-slate-800/50 hover:border-emerald-500/30 transition-all group"
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[9px] font-black uppercase text-blue-400 px-1.5 py-0.5 bg-blue-400/10 rounded-md border border-blue-400/20">
                    {snippet.category}
                  </span>
                  <button 
                    onClick={() => onInsertCode(snippet.code)}
                    className="p-1 text-slate-500 hover:text-emerald-400 transition-colors"
                  >
                    <TerminalIcon size={14} />
                  </button>
                </div>
                <h3 className="text-xs font-black text-slate-200 mb-1 uppercase tracking-tight">{snippet.title}</h3>
                <p className="text-[10px] text-slate-500 mb-3 line-clamp-2 italic">{snippet.description}</p>
                <div className="p-2 bg-slate-900 rounded-lg font-mono text-[9px] text-slate-400 overflow-x-auto border border-white/5">
                  {snippet.code}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="space-y-4">
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-2xl p-4 mb-4">
              <p className="text-[10px] text-emerald-200 leading-relaxed italic">
                "Spectre Intelligence analyzes the operational state to provide tactical guidance and automated reconnaissance paths."
              </p>
            </div>
            
            <button 
              onClick={fetchAiSuggestions}
              disabled={isLoading}
              className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl text-xs font-black shadow-lg transition-all flex items-center justify-center gap-2"
            >
              {isLoading ? <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" /> : <Sparkles size={14} />}
              {isLoading ? 'ANALYZING...' : 'GET TACTICAL INTEL'}
            </button>

            {aiSuggestions && (
              <div className="mt-4 p-4 bg-slate-900 border border-slate-700 rounded-2xl text-[10px] font-mono text-slate-300 whitespace-pre-wrap leading-relaxed animate-in fade-in duration-500 border border-emerald-500/10">
                {aiSuggestions}
              </div>
            )}

            {!aiSuggestions && !isLoading && (
              <div className="text-center py-12 text-slate-600 opacity-20">
                <Search size={32} className="mx-auto mb-2" />
                <p className="text-[10px] font-black uppercase tracking-widest">Awaiting Operational Context</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default LabAssistant;
