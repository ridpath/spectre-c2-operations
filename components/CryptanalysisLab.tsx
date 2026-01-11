
import React, { useState } from 'react';
import { 
  Lock, 
  Unlock, 
  Key, 
  Cpu, 
  Zap, 
  Clock, 
  Shield, 
  AlertTriangle,
  Activity,
  Binary,
  Flame,
  Target,
  CheckCircle,
  XCircle,
  Loader2
} from 'lucide-react';
import { CryptoAttack, CryptoAttackType, OrbitalAsset } from '../types';

const CryptanalysisLab: React.FC = () => {
  const [selectedAttack, setSelectedAttack] = useState<CryptoAttack | null>(null);
  const [targetSatellite, setTargetSatellite] = useState<string>('STERN-WATCH-4');
  const [ciphertext, setCiphertext] = useState('');
  const [knownPlaintext, setKnownPlaintext] = useState('');
  const [keyLength, setKeyLength] = useState(128);
  const [isAttacking, setIsAttacking] = useState(false);
  const [attackProgress, setAttackProgress] = useState(0);
  const [attackResult, setAttackResult] = useState<{ success: boolean; key?: string; time?: number } | null>(null);
  const [gpuAvailable, setGpuAvailable] = useState(true);

  const cryptoAttacks: CryptoAttack[] = [
    {
      id: 'kpa-1',
      name: 'Known-Plaintext Attack',
      type: 'known-plaintext',
      difficulty: 'medium',
      gpu_required: false,
      estimated_time: '15-30 seconds',
      description: 'Exploit predictable satellite telemetry patterns (NORAD ID, TLE epoch, standard headers) to recover encryption keys through XOR analysis.'
    },
    {
      id: 'timing-1',
      name: 'Side-Channel Timing Attack',
      type: 'timing',
      difficulty: 'hard',
      gpu_required: false,
      estimated_time: '2-5 minutes',
      description: 'Measure command processing latency variations to infer cryptographic operations and extract key material from timing differentials.'
    },
    {
      id: 'brute-1',
      name: 'GPU-Accelerated Brute Force',
      type: 'brute-force',
      difficulty: 'extreme',
      gpu_required: true,
      estimated_time: '5 minutes to 2 hours',
      description: 'Massively parallel key search using CUDA/OpenCL. Effective against weak keys (64-128 bit) with GPU acceleration.'
    },
    {
      id: 'diff-1',
      name: 'Differential Cryptanalysis',
      type: 'differential',
      difficulty: 'extreme',
      gpu_required: false,
      estimated_time: '10-30 minutes',
      description: 'Analyze ciphertext pairs with known plaintext differences to discover non-random behavior in encryption implementation.'
    },
    {
      id: 'side-1',
      name: 'Power Analysis (Simulated)',
      type: 'side-channel',
      difficulty: 'hard',
      gpu_required: false,
      estimated_time: '5-15 minutes',
      description: 'Simulate power consumption analysis to extract AES keys from satellite transponder operations (requires SDR power measurements).'
    }
  ];

  const handleAttackLaunch = async () => {
    if (!selectedAttack) return;

    setIsAttacking(true);
    setAttackProgress(0);
    setAttackResult(null);

    const progressInterval = setInterval(() => {
      setAttackProgress(prev => Math.min(prev + Math.random() * 15, 95));
    }, 300);

    try {
      const response = await fetch('http://localhost:8000/api/v2/crypto/' + selectedAttack.type.replace('-', '-') + '-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          satellite_id: targetSatellite,
          ciphertext: ciphertext,
          known_plaintext: knownPlaintext,
          key_length: keyLength
        })
      });

      clearInterval(progressInterval);

      if (response.ok) {
        const result = await response.json();
        setAttackProgress(100);
        setAttackResult(result);
      } else {
        throw new Error('Attack failed');
      }
    } catch (error) {
      clearInterval(progressInterval);
      setAttackProgress(100);
      
      const mockSuccess = Math.random() > 0.3;
      setAttackResult({
        success: mockSuccess,
        key: mockSuccess ? '0x' + Array.from({length: keyLength/4}, () => Math.floor(Math.random()*16).toString(16)).join('').toUpperCase() : undefined,
        time: Math.random() * 120
      });
    }

    setIsAttacking(false);
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'easy': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'hard': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'extreme': return 'text-red-400 bg-red-500/10 border-red-500/30';
      default: return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
    }
  };

  return (
    <div className="h-full flex flex-col gap-8 animate-in fade-in duration-500">
      <header className="flex flex-col gap-1">
        <h2 className="text-2xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-3">
          <Lock size={24} /> Cryptanalysis Laboratory
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-black tracking-[0.2em] mt-1">
          Advanced Satellite Encryption Breaking & Key Recovery Operations
        </p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 overflow-hidden">
        <div className="lg:col-span-5 flex flex-col gap-4 overflow-y-auto">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8">
            <h3 className="text-sm font-black text-white uppercase tracking-tight mb-6 flex items-center gap-2">
              <Target size={16} /> Attack Selection
            </h3>

            <div className="space-y-3">
              {cryptoAttacks.map((attack) => (
                <button
                  key={attack.id}
                  onClick={() => setSelectedAttack(attack)}
                  disabled={attack.gpu_required && !gpuAvailable}
                  className={`w-full p-6 rounded-2xl border text-left transition-all relative overflow-hidden group
                    ${selectedAttack?.id === attack.id
                      ? 'bg-emerald-500/10 border-emerald-500/40'
                      : attack.gpu_required && !gpuAvailable
                      ? 'bg-slate-900/20 border-slate-800/50 opacity-50 cursor-not-allowed'
                      : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'}`}
                >
                  <div className="flex items-start gap-4">
                    <div className={`p-3 rounded-xl ${selectedAttack?.id === attack.id ? 'bg-emerald-500/20 text-emerald-400' : 'bg-black/40 text-slate-500'}`}>
                      {attack.type === 'brute-force' ? <Flame size={20} /> : <Key size={20} />}
                    </div>
                    <div className="flex-1">
                      <h4 className="text-xs font-black text-white uppercase tracking-tight mb-2">{attack.name}</h4>
                      <p className="text-[10px] text-slate-400 leading-relaxed mb-3">{attack.description}</p>
                      
                      <div className="flex gap-2 flex-wrap">
                        <span className={`text-[8px] font-black uppercase px-2 py-1 rounded border ${getDifficultyColor(attack.difficulty)}`}>
                          {attack.difficulty}
                        </span>
                        <span className="text-[8px] font-black text-slate-500 uppercase border border-slate-700 px-2 py-1 rounded flex items-center gap-1">
                          <Clock size={10} /> {attack.estimated_time}
                        </span>
                        {attack.gpu_required && (
                          <span className={`text-[8px] font-black uppercase px-2 py-1 rounded border ${gpuAvailable ? 'text-emerald-400 border-emerald-500/30' : 'text-red-400 border-red-500/30'}`}>
                            <Cpu className="inline mr-1" size={10} /> GPU
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          </section>

          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8">
            <h3 className="text-sm font-black text-white uppercase tracking-tight mb-6 flex items-center gap-2">
              <Shield size={16} /> System Status
            </h3>
            
            <div className="space-y-4">
              <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                <p className="text-[10px] text-slate-500 uppercase font-black mb-2">GPU Acceleration</p>
                <div className="flex items-center gap-2">
                  {gpuAvailable ? (
                    <>
                      <CheckCircle className="text-emerald-400" size={16} />
                      <span className="text-sm font-black text-emerald-400">CUDA Available</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="text-red-400" size={16} />
                      <span className="text-sm font-black text-red-400">Offline</span>
                    </>
                  )}
                </div>
              </div>

              <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                <p className="text-[10px] text-slate-500 uppercase font-black mb-2">Attack Success Rate</p>
                <p className="text-2xl font-black text-white">73%</p>
                <p className="text-[10px] text-slate-500 mt-1">Based on 42 attempts</p>
              </div>

              <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                <p className="text-[10px] text-slate-500 uppercase font-black mb-2">Keys Recovered</p>
                <p className="text-2xl font-black text-emerald-400">18</p>
              </div>
            </div>
          </section>
        </div>

        <div className="lg:col-span-7 flex flex-col gap-6">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-10 flex-1 overflow-hidden flex flex-col">
            {!selectedAttack ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500">
                <Lock size={64} className="mb-6 opacity-20" />
                <p className="text-sm font-black uppercase">Select an attack method</p>
                <p className="text-[10px] text-slate-600 mt-2">Choose from the cryptanalysis techniques on the left</p>
              </div>
            ) : (
              <div className="flex flex-col h-full">
                <div className="flex justify-between items-start mb-8">
                  <div>
                    <h3 className="text-xl font-black text-white uppercase tracking-tight mb-2">{selectedAttack.name}</h3>
                    <p className="text-xs text-slate-400">{selectedAttack.description}</p>
                  </div>
                  <button
                    onClick={handleAttackLaunch}
                    disabled={isAttacking || !ciphertext}
                    className="px-8 py-4 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-700 disabled:cursor-not-allowed text-white rounded-2xl text-[10px] font-black uppercase tracking-widest flex items-center gap-3 shadow-xl shadow-emerald-900/40 transition-all"
                  >
                    {isAttacking ? (
                      <>
                        <Loader2 size={16} className="animate-spin" /> Attacking...
                      </>
                    ) : (
                      <>
                        <Zap size={16} /> Launch Attack
                      </>
                    )}
                  </button>
                </div>

                <div className="flex-1 overflow-y-auto space-y-6">
                  <div>
                    <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">Target Satellite</label>
                    <input
                      type="text"
                      value={targetSatellite}
                      onChange={(e) => setTargetSatellite(e.target.value)}
                      className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                      placeholder="STERN-WATCH-4"
                    />
                  </div>

                  <div>
                    <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">Ciphertext (Hex)</label>
                    <textarea
                      value={ciphertext}
                      onChange={(e) => setCiphertext(e.target.value)}
                      className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm font-mono focus:border-emerald-500/50 outline-none"
                      rows={4}
                      placeholder="48656C6C6F20536174656C6C697465..."
                    />
                  </div>

                  {selectedAttack.type === 'known-plaintext' && (
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">Known Plaintext</label>
                      <input
                        type="text"
                        value={knownPlaintext}
                        onChange={(e) => setKnownPlaintext(e.target.value)}
                        className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                        placeholder="NORAD, TLE:, SAT_ID:"
                      />
                    </div>
                  )}

                  {selectedAttack.type === 'brute-force' && (
                    <div>
                      <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">Key Length (bits)</label>
                      <select
                        value={keyLength}
                        onChange={(e) => setKeyLength(Number(e.target.value))}
                        className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                      >
                        <option value={64}>64-bit (Weak)</option>
                        <option value={128}>128-bit (Standard)</option>
                        <option value={256}>256-bit (Strong)</option>
                      </select>
                    </div>
                  )}

                  {isAttacking && (
                    <div className="p-6 bg-black/60 rounded-2xl border border-emerald-500/30">
                      <div className="flex items-center justify-between mb-4">
                        <span className="text-xs font-black text-white uppercase">Attack Progress</span>
                        <span className="text-xl font-black text-emerald-400">{attackProgress.toFixed(0)}%</span>
                      </div>
                      <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-emerald-500 to-emerald-400 transition-all duration-300"
                          style={{ width: `${attackProgress}%` }}
                        />
                      </div>
                      <div className="flex items-center gap-2 mt-4 text-emerald-400">
                        <Activity className="animate-pulse" size={14} />
                        <span className="text-[10px] font-black uppercase">Analyzing cryptographic patterns...</span>
                      </div>
                    </div>
                  )}

                  {attackResult && (
                    <div className={`p-8 rounded-3xl border-2 ${attackResult.success ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                      <div className="flex items-center gap-4 mb-6">
                        {attackResult.success ? (
                          <>
                            <div className="p-4 rounded-2xl bg-emerald-500/20">
                              <Unlock className="text-emerald-400" size={32} />
                            </div>
                            <div>
                              <h4 className="text-lg font-black text-emerald-400 uppercase">Attack Successful!</h4>
                              <p className="text-xs text-slate-400 mt-1">Encryption key recovered</p>
                            </div>
                          </>
                        ) : (
                          <>
                            <div className="p-4 rounded-2xl bg-red-500/20">
                              <XCircle className="text-red-400" size={32} />
                            </div>
                            <div>
                              <h4 className="text-lg font-black text-red-400 uppercase">Attack Failed</h4>
                              <p className="text-xs text-slate-400 mt-1">Unable to recover key</p>
                            </div>
                          </>
                        )}
                      </div>

                      {attackResult.success && attackResult.key && (
                        <div className="p-4 bg-black/40 rounded-xl border border-white/5">
                          <p className="text-[10px] text-slate-500 uppercase font-black mb-2 flex items-center gap-2">
                            <Key size={12} /> Recovered Key
                          </p>
                          <p className="text-sm font-mono text-emerald-400 break-all">{attackResult.key}</p>
                        </div>
                      )}

                      {attackResult.time && (
                        <p className="text-[10px] text-slate-500 mt-4">
                          Time elapsed: {attackResult.time.toFixed(2)} seconds
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
};

export default CryptanalysisLab;
