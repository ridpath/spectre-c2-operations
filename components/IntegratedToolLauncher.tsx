import React, { useState } from 'react';
import { Wrench, Play, Terminal, CheckCircle, XCircle, Settings } from 'lucide-react';
import { SDRTool } from '../types';

interface IntegratedToolLauncherProps {
  onLaunchTool: (tool: SDRTool, params: Record<string, string>) => void;
}

const IntegratedToolLauncher: React.FC<IntegratedToolLauncherProps> = ({ onLaunchTool }) => {
  const [selectedTool, setSelectedTool] = useState<SDRTool | null>(null);
  const [params, setParams] = useState<Record<string, string>>({});
  const [category, setCategory] = useState<'all' | 'receiver' | 'transmitter' | 'analyzer' | 'decoder'>('all');

  const tools: SDRTool[] = [
    {
      id: 'rtl-sdr',
      name: 'RTL-SDR',
      command: 'rtl_sdr',
      category: 'receiver',
      description: 'Record IQ samples from RTL-SDR dongle',
      installCommand: 'sudo apt install rtl-sdr',
      configTemplate: '-f {FREQ} -s {RATE} -g {GAIN} {OUTFILE}'
    },
    {
      id: 'hackrf-transfer',
      name: 'HackRF Transfer',
      command: 'hackrf_transfer',
      category: 'transmitter',
      description: 'Transmit or receive with HackRF One',
      installCommand: 'sudo apt install hackrf',
      configTemplate: '-t {FILE} -f {FREQ} -s {RATE} -x {GAIN}'
    },
    {
      id: 'gr-satellites',
      name: 'gr-satellites',
      command: 'gr-satellites',
      category: 'decoder',
      description: 'Decode satellite telemetry frames',
      installCommand: 'pip install gr-satellites',
      configTemplate: '{SATELLITE} --iq-file {FILE} --samp-rate {RATE}'
    },
    {
      id: 'gqrx',
      name: 'GQRX',
      command: 'gqrx',
      category: 'analyzer',
      description: 'Software-defined radio receiver with spectrum analysis',
      installCommand: 'sudo apt install gqrx-sdr',
      configTemplate: ''
    },
    {
      id: 'rtl-power',
      name: 'RTL Power',
      command: 'rtl_power',
      category: 'analyzer',
      description: 'Scan frequency ranges for signal strength',
      installCommand: 'sudo apt install rtl-sdr',
      configTemplate: '-f {START}M:{END}M -g {GAIN} -i {INTERVAL}s'
    },
    {
      id: 'hackrf-sweep',
      name: 'HackRF Sweep',
      command: 'hackrf_sweep',
      category: 'analyzer',
      description: 'Wideband spectrum analysis with HackRF',
      installCommand: 'sudo apt install hackrf',
      configTemplate: '-f {START}:{END} -w {BANDWIDTH}'
    },
    {
      id: 'direwolf',
      name: 'Direwolf',
      command: 'direwolf',
      category: 'decoder',
      description: 'AX.25 packet decoder for amateur radio',
      installCommand: 'sudo apt install direwolf',
      configTemplate: '-r {RATE} -B {BAUD} {AUDIOFILE}'
    },
    {
      id: 'gnuradio',
      name: 'GNU Radio Companion',
      command: 'gnuradio-companion',
      category: 'analyzer',
      description: 'Visual SDR signal processing framework',
      installCommand: 'sudo apt install gnuradio',
      configTemplate: '{FLOWGRAPH}'
    },
    {
      id: 'uhd-fft',
      name: 'UHD FFT',
      command: 'uhd_fft',
      category: 'analyzer',
      description: 'Real-time spectrum analyzer for USRP',
      installCommand: 'sudo apt install uhd-host',
      configTemplate: '-f {FREQ} -s {RATE} -g {GAIN}'
    },
    {
      id: 'soapy-remote',
      name: 'SoapySDR Remote',
      command: 'SoapySDRServer',
      category: 'receiver',
      description: 'Network-accessible SDR server',
      installCommand: 'sudo apt install soapysdr-server',
      configTemplate: '--bind=0.0.0.0'
    }
  ];

  const filteredTools = tools.filter(t => category === 'all' || t.category === category);

  const getCategoryIcon = (cat: SDRTool['category']) => {
    switch (cat) {
      case 'receiver': return 'RX';
      case 'transmitter': return 'TX';
      case 'analyzer': return 'AN';
      case 'decoder': return 'DC';
    }
  };

  return (
    <div className="h-full flex flex-col gap-6">
      <header>
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <Wrench size={20} /> SDR Tool Launcher
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">
          Integrated Satellite Analysis Tools
        </p>
      </header>

      <div className="flex gap-2">
        <button
          onClick={() => setCategory('all')}
          className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${
            category === 'all' ? 'bg-emerald-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          All Tools
        </button>
        <button
          onClick={() => setCategory('receiver')}
          className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${
            category === 'receiver' ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          Receivers
        </button>
        <button
          onClick={() => setCategory('transmitter')}
          className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${
            category === 'transmitter' ? 'bg-red-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          Transmitters
        </button>
        <button
          onClick={() => setCategory('analyzer')}
          className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${
            category === 'analyzer' ? 'bg-purple-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          Analyzers
        </button>
        <button
          onClick={() => setCategory('decoder')}
          className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${
            category === 'decoder' ? 'bg-yellow-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'
          }`}
        >
          Decoders
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 flex-1 overflow-hidden">
        <div className="lg:col-span-5 flex flex-col gap-3 overflow-y-auto pr-2">
          {filteredTools.map(tool => (
            <button
              key={tool.id}
              onClick={() => {
                setSelectedTool(tool);
                setParams({});
              }}
              className={`text-left p-4 rounded-2xl border transition-all ${
                selectedTool?.id === tool.id
                  ? 'bg-emerald-500/10 border-emerald-500/30'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start gap-3 mb-2">
                <div className="text-2xl">{getCategoryIcon(tool.category)}</div>
                <div className="flex-1">
                  <div className="text-sm font-black text-slate-300 mb-1">{tool.name}</div>
                  <div className="text-xs text-slate-500">{tool.description}</div>
                </div>
              </div>
              <div className="flex items-center gap-2 mt-2">
                <Terminal size={10} className="text-slate-600" />
                <span className="text-xs font-mono text-slate-600">{tool.command}</span>
              </div>
            </button>
          ))}

          {filteredTools.length === 0 && (
            <div className="text-center py-12 text-slate-600">
              <Wrench size={40} className="mx-auto mb-3 opacity-30" />
              <div className="text-sm font-bold uppercase">No Tools Found</div>
            </div>
          )}
        </div>

        <div className="lg:col-span-7 flex flex-col gap-4">
          {selectedTool ? (
            <>
              <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex items-start gap-3">
                  <div className="text-3xl">{getCategoryIcon(selectedTool.category)}</div>
                  <div className="flex-1">
                    <h3 className="text-lg font-black text-emerald-400 mb-1">{selectedTool.name}</h3>
                    <p className="text-sm text-slate-400">{selectedTool.description}</p>
                  </div>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-xl p-3">
                    <span className="text-slate-600 font-bold uppercase">Command:</span>
                    <span className="font-mono text-emerald-400">{selectedTool.command}</span>
                  </div>
                  <div className="flex items-center justify-between bg-slate-950 border border-slate-800 rounded-xl p-3">
                    <span className="text-slate-600 font-bold uppercase">Category:</span>
                    <span className="text-blue-400 uppercase">{selectedTool.category}</span>
                  </div>
                </div>

                {selectedTool.installCommand && (
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-3">
                    <div className="text-xs font-bold text-blue-400 uppercase mb-2">Installation</div>
                    <pre className="text-xs font-mono text-blue-300/70">
                      {selectedTool.installCommand}
                    </pre>
                  </div>
                )}
              </div>

              {selectedTool.configTemplate && (
                <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
                  <div className="text-sm font-black uppercase text-slate-400 flex items-center gap-2">
                    <Settings size={14} />
                    Configuration
                  </div>

                  <div className="space-y-3">
                    <div>
                      <label className="text-xs font-bold text-slate-500 uppercase mb-2 block">
                        Command Template
                      </label>
                      <div className="bg-black border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-400">
                        {selectedTool.command} {selectedTool.configTemplate}
                      </div>
                    </div>

                    <div>
                      <label className="text-xs font-bold text-slate-500 uppercase mb-2 block">
                        Custom Parameters (JSON)
                      </label>
                      <textarea
                        placeholder='{"FREQ": "437800000", "RATE": "2048000", "GAIN": "40"}'
                        value={JSON.stringify(params)}
                        onChange={(e) => {
                          try {
                            setParams(JSON.parse(e.target.value));
                          } catch {}
                        }}
                        className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm font-mono text-slate-300 outline-none focus:border-emerald-500 transition-all resize-none"
                        rows={4}
                      />
                    </div>
                  </div>
                </div>
              )}

              <div className="flex gap-3">
                <button
                  onClick={() => {
                    const cmd = `${selectedTool.command} ${selectedTool.configTemplate}`;
                    navigator.clipboard.writeText(cmd);
                  }}
                  className="flex-1 py-3 bg-slate-800 hover:bg-slate-700 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
                >
                  <Terminal size={16} />
                  Copy Command
                </button>
                <button
                  onClick={() => onLaunchTool(selectedTool, params)}
                  className="flex-1 py-3 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
                >
                  <Play size={16} />
                  Launch Tool
                </button>
              </div>

              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 text-xs text-yellow-400">
                <div className="font-bold mb-1 uppercase">Note</div>
                <div className="text-yellow-300/70">
                  Ensure the tool is installed on your system. Click "Copy Command" to get the installation command.
                </div>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-center text-slate-600">
              <div>
                <Wrench size={80} className="mx-auto mb-6 opacity-20" />
                <div className="text-xl font-bold uppercase mb-3">Select a Tool</div>
                <div className="text-sm">Choose an SDR tool from the list to configure and launch</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default IntegratedToolLauncher;
