import React, { useState, useEffect } from 'react';
import { Package, Binary, Send, Copy, AlertTriangle, CheckCircle, Hash } from 'lucide-react';

interface CCSDSPacket {
  version: number;
  type: 'TM' | 'TC';
  apid: number;
  sequenceFlags: number;
  sequenceCount: number;
  dataLength: number;
  payload: string;
}

interface CCSDSPacketBuilderProps {
  onTransmit: (packet: string) => void;
  onCopy: (packet: string) => void;
}

const CCSDSPacketBuilder: React.FC<CCSDSPacketBuilderProps> = ({ onTransmit, onCopy }) => {
  const [packet, setPacket] = useState<CCSDSPacket>({
    version: 0,
    type: 'TC',
    apid: 1,
    sequenceFlags: 3,
    sequenceCount: 0,
    dataLength: 0,
    payload: ''
  });

  const [hexOutput, setHexOutput] = useState('');
  const [crcValid, setCrcValid] = useState(true);

  useEffect(() => {
    buildHexPacket();
  }, [packet]);

  const buildHexPacket = () => {
    const versionBits = packet.version & 0x07;
    const typeBit = packet.type === 'TC' ? 1 : 0;
    const apidBits = packet.apid & 0x7FF;
    
    const byte0 = (versionBits << 5) | (typeBit << 4) | ((apidBits >> 8) & 0x0F);
    const byte1 = apidBits & 0xFF;
    
    const byte2 = ((packet.sequenceFlags & 0x03) << 6) | ((packet.sequenceCount >> 8) & 0x3F);
    const byte3 = packet.sequenceCount & 0xFF;
    
    const payloadBytes = packet.payload ? hexToBytes(packet.payload) : [];
    const dataLen = payloadBytes.length - 1;
    
    const byte4 = (dataLen >> 8) & 0xFF;
    const byte5 = dataLen & 0xFF;
    
    const header = [byte0, byte1, byte2, byte3, byte4, byte5];
    const fullPacket = [...header, ...payloadBytes];
    
    const crc = calculateCRC16(fullPacket);
    fullPacket.push((crc >> 8) & 0xFF);
    fullPacket.push(crc & 0xFF);
    
    const hex = fullPacket.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
    setHexOutput(hex);
    
    setPacket(prev => ({ ...prev, dataLength: payloadBytes.length }));
  };

  const hexToBytes = (hex: string): number[] => {
    const cleaned = hex.replace(/[^0-9A-Fa-f]/g, '');
    const bytes: number[] = [];
    for (let i = 0; i < cleaned.length; i += 2) {
      bytes.push(parseInt(cleaned.substring(i, i + 2), 16));
    }
    return bytes;
  };

  const calculateCRC16 = (data: number[]): number => {
    let crc = 0xFFFF;
    for (const byte of data) {
      crc ^= byte << 8;
      for (let i = 0; i < 8; i++) {
        if (crc & 0x8000) {
          crc = (crc << 1) ^ 0x1021;
        } else {
          crc = crc << 1;
        }
      }
    }
    return crc & 0xFFFF;
  };

  const presets = [
    { name: 'Telemetry Request', apid: 1, payload: 'AA BB CC DD' },
    { name: 'Command Echo', apid: 5, payload: 'FF 00 FF 00' },
    { name: 'Housekeeping Poll', apid: 10, payload: '01 02 03 04 05' },
    { name: 'Time Sync', apid: 15, payload: 'DE AD BE EF' }
  ];

  return (
    <div className="h-full flex flex-col gap-6">
      <header>
        <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
          <Package size={20} /> CCSDS Packet Builder
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">
          Visual Space Packet Construction
        </p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 overflow-hidden">
        <div className="flex flex-col gap-4 overflow-y-auto pr-2">
          <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="text-sm font-black uppercase text-slate-400 flex items-center gap-2">
              <Binary size={14} />
              Primary Header
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-500 uppercase">Version</label>
                <input
                  type="number"
                  min="0"
                  max="7"
                  value={packet.version}
                  onChange={(e) => setPacket({ ...packet, version: parseInt(e.target.value) || 0 })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm font-mono text-slate-300 outline-none focus:border-emerald-500 transition-all"
                />
                <div className="text-[10px] text-slate-600">0-7 (3 bits)</div>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-500 uppercase">Type</label>
                <select
                  value={packet.type}
                  onChange={(e) => setPacket({ ...packet, type: e.target.value as 'TM' | 'TC' })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm font-mono text-slate-300 outline-none focus:border-emerald-500 transition-all"
                >
                  <option value="TM">TM (Telemetry)</option>
                  <option value="TC">TC (Telecommand)</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-500 uppercase">APID</label>
                <input
                  type="number"
                  min="0"
                  max="2047"
                  value={packet.apid}
                  onChange={(e) => setPacket({ ...packet, apid: parseInt(e.target.value) || 0 })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm font-mono text-slate-300 outline-none focus:border-emerald-500 transition-all"
                />
                <div className="text-[10px] text-slate-600">Application Process ID (0-2047)</div>
              </div>

              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-500 uppercase">Sequence Flags</label>
                <select
                  value={packet.sequenceFlags}
                  onChange={(e) => setPacket({ ...packet, sequenceFlags: parseInt(e.target.value) })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm font-mono text-slate-300 outline-none focus:border-emerald-500 transition-all"
                >
                  <option value="0">Continuation (0)</option>
                  <option value="1">First (1)</option>
                  <option value="2">Last (2)</option>
                  <option value="3">Standalone (3)</option>
                </select>
              </div>

              <div className="col-span-2 space-y-2">
                <label className="text-xs font-bold text-slate-500 uppercase">Sequence Count</label>
                <input
                  type="number"
                  min="0"
                  max="16383"
                  value={packet.sequenceCount}
                  onChange={(e) => setPacket({ ...packet, sequenceCount: parseInt(e.target.value) || 0 })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm font-mono text-slate-300 outline-none focus:border-emerald-500 transition-all"
                />
                <div className="text-[10px] text-slate-600">Packet sequence number (0-16383)</div>
              </div>
            </div>
          </div>

          <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="text-sm font-black uppercase text-slate-400 flex items-center gap-2">
              <Hash size={14} />
              Payload Data
            </div>

            <div className="space-y-2">
              <label className="text-xs font-bold text-slate-500 uppercase">Hex Payload</label>
              <textarea
                value={packet.payload}
                onChange={(e) => setPacket({ ...packet, payload: e.target.value })}
                placeholder="AA BB CC DD EE FF..."
                className="w-full bg-black/40 border border-slate-800 rounded-xl px-3 py-2 text-sm font-mono text-slate-300 outline-none focus:border-emerald-500 transition-all resize-none"
                rows={4}
              />
              <div className="text-[10px] text-slate-600">Space-separated hex bytes</div>
            </div>

            <div className="text-xs text-slate-500">
              <span className="font-bold">Data Length:</span> {packet.dataLength} bytes
            </div>
          </div>

          <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-4">
            <div className="text-xs font-black uppercase text-slate-600 mb-3">Quick Presets</div>
            <div className="grid grid-cols-2 gap-2">
              {presets.map((preset, idx) => (
                <button
                  key={idx}
                  onClick={() => setPacket({ ...packet, apid: preset.apid, payload: preset.payload })}
                  className="text-left text-xs px-3 py-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-400 hover:text-emerald-400 transition-all"
                >
                  {preset.name}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="flex flex-col gap-4">
          <div className="bg-slate-950 border border-slate-800 rounded-2xl p-6 flex-1 flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <div className="text-sm font-black uppercase text-slate-400">Packet Output</div>
              <div className={`flex items-center gap-1 text-xs ${crcValid ? 'text-emerald-400' : 'text-red-400'}`}>
                {crcValid ? <CheckCircle size={12} /> : <AlertTriangle size={12} />}
                CRC-16
              </div>
            </div>

            <div className="flex-1 overflow-y-auto mb-4">
              <pre className="text-xs font-mono text-emerald-400 break-all whitespace-pre-wrap leading-relaxed">
                {hexOutput || 'Configure packet parameters to generate output...'}
              </pre>
            </div>

            <div className="space-y-2 text-xs text-slate-500 border-t border-slate-800 pt-4">
              <div className="flex justify-between">
                <span className="font-bold">Total Size:</span>
                <span>{hexOutput.split(' ').length} bytes</span>
              </div>
              <div className="flex justify-between">
                <span className="font-bold">Header:</span>
                <span>6 bytes</span>
              </div>
              <div className="flex justify-between">
                <span className="font-bold">Payload:</span>
                <span>{packet.dataLength} bytes</span>
              </div>
              <div className="flex justify-between">
                <span className="font-bold">CRC:</span>
                <span>2 bytes</span>
              </div>
            </div>
          </div>

          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-2xl p-4 flex items-start gap-2">
            <AlertTriangle size={16} className="text-yellow-500 shrink-0 mt-0.5" />
            <div className="text-xs text-yellow-400">
              <div className="font-bold mb-1">Transmission Warning</div>
              <div className="text-yellow-300/70">
                Unauthorized telecommand injection may violate laws. Ensure proper authorization before transmission.
              </div>
            </div>
          </div>

          <div className="flex gap-3">
            <button
              onClick={() => onCopy(hexOutput)}
              className="flex-1 py-3 bg-slate-800 hover:bg-slate-700 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
            >
              <Copy size={16} />
              Copy Hex
            </button>
            <button
              onClick={() => onTransmit(hexOutput)}
              className="flex-1 py-3 bg-red-600 hover:bg-red-500 rounded-xl text-white font-bold text-sm flex items-center justify-center gap-2 transition-all"
            >
              <Send size={16} />
              Transmit
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CCSDSPacketBuilder;
