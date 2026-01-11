
import React, { useState, useRef } from 'react';
import Editor from '@monaco-editor/react';
import { 
  Upload, 
  Cpu, 
  Shield, 
  AlertTriangle, 
  Search, 
  Binary, 
  FileCode,
  Zap,
  Lock,
  Key,
  Bug,
  Terminal,
  Scan,
  Activity,
  HardDrive,
  CheckCircle,
  XCircle
} from 'lucide-react';
import { FirmwareAnalysis, FirmwareVulnerability, FirmwareArch } from '../types';

const FirmwareStudio: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<FirmwareAnalysis | null>(null);
  const [hexView, setHexView] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<'hex' | 'vulns' | 'strings' | 'disasm'>('hex');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFile(file);
    setIsAnalyzing(true);

    const reader = new FileReader();
    reader.onload = async (event) => {
      const arrayBuffer = event.target?.result as ArrayBuffer;
      const bytes = new Uint8Array(arrayBuffer);
      
      const hexString = Array.from(bytes.slice(0, 2048))
        .map((b, i) => {
          const hex = b.toString(16).padStart(2, '0');
          return (i % 16 === 0 ? '\n' + i.toString(16).padStart(8, '0') + ':  ' : '') + hex + ' ';
        })
        .join('');
      
      setHexView(hexString);

      try {
        const formData = new FormData();
        formData.append('firmware', file);
        
        const response = await fetch('http://localhost:8000/api/v2/firmware/upload', {
          method: 'POST',
          body: formData
        });

        if (response.ok) {
          const uploadResult = await response.json();
          const analysisResponse = await fetch(`http://localhost:8000/api/v2/firmware/${uploadResult.id}/analyze`, {
            method: 'POST'
          });
          
          if (analysisResponse.ok) {
            const analysisData = await analysisResponse.json();
            setAnalysis(analysisData);
          }
        }
      } catch (error) {
        console.log('Backend not available, using mock data');
        setAnalysis(generateMockAnalysis(file));
      }
      
      setIsAnalyzing(false);
    };
    
    reader.readAsArrayBuffer(file);
  };

  const generateMockAnalysis = (file: File): FirmwareAnalysis => {
    const vulns: FirmwareVulnerability[] = [
      {
        type: 'hardcoded_credential',
        severity: 'critical',
        offset: 0x2A40,
        description: 'Hardcoded admin password found: "satellite123"'
      },
      {
        type: 'buffer_overflow',
        severity: 'high',
        offset: 0x1580,
        description: 'Unbounded strcpy() call in command parser'
      },
      {
        type: 'weak_crypto',
        severity: 'medium',
        offset: 0x3C00,
        description: 'XOR encryption with predictable key'
      }
    ];

    return {
      id: 'fw-' + Date.now(),
      filename: file.name,
      hash: 'sha256:' + Math.random().toString(16).slice(2),
      size: file.size,
      architecture: 'ARM',
      entry_point: '0x8000',
      functions_count: 124,
      strings_count: 342,
      vulnerabilities: vulns,
      crypto_keys: ['0xDEADBEEF', '0xCAFEBABE'],
      status: 'completed'
    };
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      default: return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <Shield className="text-red-400" size={16} />;
      case 'high': return <AlertTriangle className="text-orange-400" size={16} />;
      default: return <Bug className="text-yellow-400" size={16} />;
    }
  };

  return (
    <div className="h-full flex flex-col gap-8 animate-in fade-in duration-500">
      <header className="flex flex-col gap-1">
        <h2 className="text-2xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-3">
          <FileCode size={24} /> Firmware Analysis Studio
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-black tracking-[0.2em] mt-1">
          Reverse Engineering & Vulnerability Extraction for Satellite Binaries
        </p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 overflow-hidden">
        <div className="lg:col-span-4 flex flex-col gap-4">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8">
            <h3 className="text-sm font-black text-white uppercase tracking-tight mb-6 flex items-center gap-2">
              <Upload size={16} /> Firmware Upload
            </h3>
            
            <input 
              type="file" 
              ref={fileInputRef}
              onChange={handleFileUpload}
              accept=".bin,.hex,.elf,.img"
              className="hidden"
            />
            
            <button
              onClick={() => fileInputRef.current?.click()}
              className="w-full p-8 border-2 border-dashed border-slate-700 hover:border-emerald-500/50 rounded-3xl transition-all group relative overflow-hidden"
            >
              <div className="flex flex-col items-center gap-4">
                <div className="p-4 rounded-2xl bg-emerald-500/10 text-emerald-400 group-hover:bg-emerald-500/20 transition-all">
                  <HardDrive size={32} />
                </div>
                <div className="text-center">
                  <p className="text-xs font-black text-white uppercase">Drop Binary or Click</p>
                  <p className="text-[10px] text-slate-500 mt-1">BIN, HEX, ELF, IMG</p>
                </div>
              </div>
            </button>

            {selectedFile && (
              <div className="mt-6 p-6 bg-black/40 rounded-2xl border border-white/5">
                <div className="flex items-center gap-3 mb-4">
                  <Binary className="text-emerald-400" size={20} />
                  <div className="flex-1">
                    <p className="text-xs font-black text-white truncate">{selectedFile.name}</p>
                    <p className="text-[10px] text-slate-500">{(selectedFile.size / 1024).toFixed(2)} KB</p>
                  </div>
                </div>
                
                {isAnalyzing && (
                  <div className="flex items-center gap-2 text-emerald-400">
                    <Activity className="animate-pulse" size={14} />
                    <span className="text-[10px] font-black uppercase">Analyzing...</span>
                  </div>
                )}
              </div>
            )}
          </section>

          {analysis && (
            <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 flex-1 overflow-hidden flex flex-col">
              <h3 className="text-sm font-black text-white uppercase tracking-tight mb-6 flex items-center gap-2">
                <Cpu size={16} /> Analysis Summary
              </h3>
              
              <div className="space-y-4 flex-1 overflow-y-auto">
                <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                  <p className="text-[10px] text-slate-500 uppercase font-black mb-1">Architecture</p>
                  <p className="text-sm font-black text-emerald-400">{analysis.architecture}</p>
                </div>
                
                <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                  <p className="text-[10px] text-slate-500 uppercase font-black mb-1">Entry Point</p>
                  <p className="text-sm font-mono text-white">{analysis.entry_point}</p>
                </div>
                
                <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                  <p className="text-[10px] text-slate-500 uppercase font-black mb-1">Functions</p>
                  <p className="text-sm font-black text-white">{analysis.functions_count}</p>
                </div>
                
                <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                  <p className="text-[10px] text-slate-500 uppercase font-black mb-1">Strings</p>
                  <p className="text-sm font-black text-white">{analysis.strings_count}</p>
                </div>

                <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                  <p className="text-[10px] text-slate-500 uppercase font-black mb-1">Vulnerabilities</p>
                  <p className="text-2xl font-black text-red-400">{analysis.vulnerabilities.length}</p>
                </div>

                {analysis.crypto_keys && analysis.crypto_keys.length > 0 && (
                  <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                    <p className="text-[10px] text-slate-500 uppercase font-black mb-2 flex items-center gap-2">
                      <Key size={12} /> Crypto Keys Found
                    </p>
                    <div className="space-y-1">
                      {analysis.crypto_keys.map((key, i) => (
                        <p key={i} className="text-[10px] font-mono text-emerald-400">{key}</p>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}
        </div>

        <div className="lg:col-span-8 flex flex-col gap-6">
          <div className="flex gap-2">
            {['hex', 'vulns', 'strings', 'disasm'].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab as any)}
                className={`px-6 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all
                  ${activeTab === tab 
                    ? 'bg-emerald-600 text-white' 
                    : 'bg-slate-900/40 text-slate-500 hover:text-white border border-slate-800'}`}
              >
                {tab}
              </button>
            ))}
          </div>

          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-10 flex-1 overflow-hidden flex flex-col">
            {activeTab === 'hex' && (
              <div className="flex-1 overflow-hidden">
                <Editor
                  height="100%"
                  defaultLanguage="plaintext"
                  value={hexView || '// Upload firmware to view hex dump'}
                  theme="vs-dark"
                  options={{
                    readOnly: true,
                    minimap: { enabled: false },
                    fontSize: 12,
                    fontFamily: 'monospace',
                    scrollBeyondLastLine: false
                  }}
                />
              </div>
            )}

            {activeTab === 'vulns' && analysis && (
              <div className="flex-1 overflow-y-auto space-y-4">
                {analysis.vulnerabilities.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-500">
                    <CheckCircle size={48} className="mb-4" />
                    <p className="text-sm font-black uppercase">No vulnerabilities found</p>
                  </div>
                ) : (
                  analysis.vulnerabilities.map((vuln, i) => (
                    <div 
                      key={i} 
                      className={`p-6 rounded-3xl border ${getSeverityColor(vuln.severity)}`}
                    >
                      <div className="flex items-start gap-4">
                        <div className="mt-1">
                          {getSeverityIcon(vuln.severity)}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center gap-3 mb-3">
                            <span className={`text-[8px] font-black uppercase px-2 py-1 rounded border ${getSeverityColor(vuln.severity)}`}>
                              {vuln.severity}
                            </span>
                            <span className="text-[10px] font-black text-slate-400 uppercase">
                              {vuln.type.replace(/_/g, ' ')}
                            </span>
                          </div>
                          <p className="text-sm text-white mb-2">{vuln.description}</p>
                          {vuln.offset !== undefined && (
                            <p className="text-[10px] font-mono text-slate-500">
                              Offset: 0x{vuln.offset.toString(16).toUpperCase()}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}

            {activeTab === 'strings' && (
              <div className="flex-1 overflow-y-auto">
                <div className="space-y-2 font-mono text-xs text-slate-400">
                  {['NORAD_ID: 43105', 'admin:satellite123', '/bin/sh', 'AES_KEY=0xDEADBEEF', 'Command received', 'Telemetry OK', 'ERROR: Buffer overflow'].map((str, i) => (
                    <div key={i} className="p-2 bg-black/40 rounded border border-white/5 hover:border-emerald-500/30 transition-colors">
                      {str}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === 'disasm' && (
              <div className="flex-1 overflow-y-auto">
                <div className="space-y-1 font-mono text-xs">
                  {[
                    '0x8000:  push   {r4, r5, r6, lr}',
                    '0x8004:  mov    r4, r0',
                    '0x8008:  ldr    r5, [pc, #0x40]',
                    '0x800c:  bl     0x9200',
                    '0x8010:  cmp    r0, #0',
                    '0x8014:  beq    0x8030'
                  ].map((line, i) => (
                    <div key={i} className="p-2 hover:bg-emerald-500/10 transition-colors">
                      <span className="text-slate-500">{line.split(':')[0]}:</span>
                      <span className="text-white ml-4">{line.split(':').slice(1).join(':')}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
};

export default FirmwareStudio;
