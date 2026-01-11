
import React, { useState } from 'react';
import { 
  Calculator, 
  Radio, 
  TowerControl, 
  Satellite, 
  Zap, 
  Activity,
  CheckCircle,
  XCircle,
  ArrowRight,
  Cloud
} from 'lucide-react';
import { LinkBudgetParams, LinkBudgetResult } from '../types';

const LinkBudgetCalculator: React.FC = () => {
  const [params, setParams] = useState<LinkBudgetParams>({
    frequency_hz: 2.2e9,
    distance_km: 540,
    tx_power_dbm: 40,
    tx_antenna_gain_dbi: 20,
    rx_antenna_gain_dbi: 15,
    system_noise_temp_k: 290,
    atmospheric_loss_db: 0.5,
    rain_loss_db: 0
  });

  const [result, setResult] = useState<LinkBudgetResult | null>(null);

  const calculateLinkBudget = () => {
    const freq_ghz = params.frequency_hz / 1e9;
    const distance_m = params.distance_km * 1000;

    const fspl_db = 20 * Math.log10(distance_m) + 20 * Math.log10(params.frequency_hz) - 147.55;
    
    const total_loss_db = fspl_db + (params.atmospheric_loss_db || 0) + (params.rain_loss_db || 0);
    
    const received_power_dbm = params.tx_power_dbm + params.tx_antenna_gain_dbi + params.rx_antenna_gain_dbi - total_loss_db;
    
    const boltzmann_k = -228.6;
    const bandwidth_hz = 1e6;
    const noise_power_dbm = boltzmann_k + 10 * Math.log10(params.system_noise_temp_k) + 10 * Math.log10(bandwidth_hz) + 30;
    
    const snr_db = received_power_dbm - noise_power_dbm;
    
    const required_snr = 10;
    const margin_db = snr_db - required_snr;

    setResult({
      fspl_db,
      total_loss_db,
      received_power_dbm,
      snr_db,
      margin_db,
      link_viable: margin_db > 0
    });
  };

  const updateParam = (key: keyof LinkBudgetParams, value: number) => {
    setParams(prev => ({ ...prev, [key]: value }));
    setResult(null);
  };

  const presets = {
    'LEO UHF Uplink': {
      frequency_hz: 435e6,
      distance_km: 600,
      tx_power_dbm: 40,
      tx_antenna_gain_dbi: 12,
      rx_antenna_gain_dbi: 0,
      system_noise_temp_k: 400
    },
    'S-Band Downlink': {
      frequency_hz: 2.2e9,
      distance_km: 540,
      tx_power_dbm: 30,
      tx_antenna_gain_dbi: 10,
      rx_antenna_gain_dbi: 20,
      system_noise_temp_k: 290
    },
    'X-Band Relay': {
      frequency_hz: 8.4e9,
      distance_km: 800,
      tx_power_dbm: 45,
      tx_antenna_gain_dbi: 35,
      rx_antenna_gain_dbi: 40,
      system_noise_temp_k: 200
    }
  };

  const loadPreset = (presetName: string) => {
    const preset = presets[presetName as keyof typeof presets];
    setParams(prev => ({ ...prev, ...preset }));
    setResult(null);
  };

  return (
    <div className="h-full flex flex-col gap-8 animate-in fade-in duration-500">
      <header className="flex flex-col gap-1">
        <h2 className="text-2xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-3">
          <Calculator size={24} /> Link Budget Calculator
        </h2>
        <p className="text-[10px] text-slate-500 uppercase font-black tracking-[0.2em] mt-1">
          Precision RF Signal Planning for Satellite Uplink/Downlink Operations
        </p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-8 overflow-hidden">
        <div className="lg:col-span-5 flex flex-col gap-4 overflow-y-auto">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-sm font-black text-white uppercase tracking-tight flex items-center gap-2">
                <Zap size={16} /> Quick Presets
              </h3>
            </div>

            <div className="space-y-2">
              {Object.keys(presets).map((presetName) => (
                <button
                  key={presetName}
                  onClick={() => loadPreset(presetName)}
                  className="w-full p-4 bg-slate-900/40 hover:bg-emerald-500/10 border border-slate-800 hover:border-emerald-500/30 rounded-xl text-left transition-all"
                >
                  <p className="text-xs font-black text-white uppercase">{presetName}</p>
                  <p className="text-[10px] text-slate-500 mt-1">
                    {(presets[presetName as keyof typeof presets].frequency_hz / 1e9).toFixed(2)} GHz
                  </p>
                </button>
              ))}
            </div>
          </section>

          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-8 flex-1 overflow-y-auto">
            <h3 className="text-sm font-black text-white uppercase tracking-tight mb-6 flex items-center gap-2">
              <Radio size={16} /> Link Parameters
            </h3>

            <div className="space-y-6">
              <div>
                <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">Frequency (GHz)</label>
                <input
                  type="number"
                  value={(params.frequency_hz / 1e9).toFixed(3)}
                  onChange={(e) => updateParam('frequency_hz', parseFloat(e.target.value) * 1e9)}
                  step="0.1"
                  className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">Distance (km)</label>
                <input
                  type="number"
                  value={params.distance_km}
                  onChange={(e) => updateParam('distance_km', parseFloat(e.target.value))}
                  className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">TX Power (dBm)</label>
                <input
                  type="number"
                  value={params.tx_power_dbm}
                  onChange={(e) => updateParam('tx_power_dbm', parseFloat(e.target.value))}
                  className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">TX Antenna Gain (dBi)</label>
                <input
                  type="number"
                  value={params.tx_antenna_gain_dbi}
                  onChange={(e) => updateParam('tx_antenna_gain_dbi', parseFloat(e.target.value))}
                  className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">RX Antenna Gain (dBi)</label>
                <input
                  type="number"
                  value={params.rx_antenna_gain_dbi}
                  onChange={(e) => updateParam('rx_antenna_gain_dbi', parseFloat(e.target.value))}
                  className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">System Noise Temp (K)</label>
                <input
                  type="number"
                  value={params.system_noise_temp_k}
                  onChange={(e) => updateParam('system_noise_temp_k', parseFloat(e.target.value))}
                  className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block flex items-center gap-2">
                  <Cloud size={10} /> Atmospheric Loss (dB)
                </label>
                <input
                  type="number"
                  value={params.atmospheric_loss_db || 0}
                  onChange={(e) => updateParam('atmospheric_loss_db', parseFloat(e.target.value))}
                  step="0.1"
                  className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 uppercase font-black mb-2 block">Rain Loss (dB)</label>
                <input
                  type="number"
                  value={params.rain_loss_db || 0}
                  onChange={(e) => updateParam('rain_loss_db', parseFloat(e.target.value))}
                  step="0.1"
                  className="w-full px-4 py-3 bg-black/40 border border-white/10 rounded-xl text-white text-sm focus:border-emerald-500/50 outline-none"
                />
              </div>

              <button
                onClick={calculateLinkBudget}
                className="w-full px-6 py-4 bg-emerald-600 hover:bg-emerald-500 text-white rounded-2xl text-[10px] font-black uppercase tracking-widest flex items-center justify-center gap-3 shadow-xl shadow-emerald-900/40 transition-all"
              >
                <Calculator size={16} /> Calculate Link Budget
              </button>
            </div>
          </section>
        </div>

        <div className="lg:col-span-7 flex flex-col gap-6">
          <section className="bg-slate-900/40 border border-slate-800 rounded-[2.5rem] p-10 flex-1 overflow-hidden flex flex-col">
            {!result ? (
              <div className="flex flex-col items-center justify-center h-full text-slate-500">
                <Calculator size={64} className="mb-6 opacity-20" />
                <p className="text-sm font-black uppercase">Configure and Calculate</p>
                <p className="text-[10px] text-slate-600 mt-2">Enter link parameters and click Calculate to see results</p>
              </div>
            ) : (
              <div className="flex flex-col h-full">
                <h3 className="text-xl font-black text-white uppercase tracking-tight mb-8">Link Budget Analysis</h3>

                <div className="bg-black/40 border border-white/5 rounded-3xl p-8 mb-8">
                  <div className="flex items-center gap-4 mb-6">
                    <TowerControl className="text-emerald-400" size={32} />
                    <ArrowRight className="text-slate-600" size={24} />
                    <Satellite className="text-blue-400" size={32} />
                    <ArrowRight className="text-slate-600" size={24} />
                    <Radio className="text-purple-400" size={32} />
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 bg-slate-900/40 rounded-xl border border-white/5">
                      <p className="text-[10px] text-slate-500 uppercase font-black mb-2">Frequency</p>
                      <p className="text-lg font-black text-white">{(params.frequency_hz / 1e9).toFixed(3)} GHz</p>
                    </div>
                    <div className="p-4 bg-slate-900/40 rounded-xl border border-white/5">
                      <p className="text-[10px] text-slate-500 uppercase font-black mb-2">Distance</p>
                      <p className="text-lg font-black text-white">{params.distance_km} km</p>
                    </div>
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-6 bg-black/40 rounded-2xl border border-white/5">
                      <p className="text-[10px] text-slate-500 uppercase font-black mb-2">Free Space Path Loss</p>
                      <p className="text-3xl font-black text-orange-400">{result.fspl_db.toFixed(2)} dB</p>
                    </div>

                    <div className="p-6 bg-black/40 rounded-2xl border border-white/5">
                      <p className="text-[10px] text-slate-500 uppercase font-black mb-2">Total Loss</p>
                      <p className="text-3xl font-black text-red-400">{result.total_loss_db.toFixed(2)} dB</p>
                    </div>

                    <div className="p-6 bg-black/40 rounded-2xl border border-white/5">
                      <p className="text-[10px] text-slate-500 uppercase font-black mb-2">Received Power</p>
                      <p className="text-3xl font-black text-blue-400">{result.received_power_dbm.toFixed(2)} dBm</p>
                    </div>

                    <div className="p-6 bg-black/40 rounded-2xl border border-white/5">
                      <p className="text-[10px] text-slate-500 uppercase font-black mb-2">Signal-to-Noise Ratio</p>
                      <p className="text-3xl font-black text-emerald-400">{result.snr_db.toFixed(2)} dB</p>
                    </div>
                  </div>

                  <div className={`p-8 rounded-3xl border-2 ${result.link_viable ? 'bg-emerald-500/10 border-emerald-500/30' : 'bg-red-500/10 border-red-500/30'}`}>
                    <div className="flex items-center gap-6">
                      <div className={`p-5 rounded-2xl ${result.link_viable ? 'bg-emerald-500/20' : 'bg-red-500/20'}`}>
                        {result.link_viable ? (
                          <CheckCircle className="text-emerald-400" size={48} />
                        ) : (
                          <XCircle className="text-red-400" size={48} />
                        )}
                      </div>
                      <div className="flex-1">
                        <h4 className={`text-2xl font-black uppercase mb-2 ${result.link_viable ? 'text-emerald-400' : 'text-red-400'}`}>
                          {result.link_viable ? 'Link Viable' : 'Link Not Viable'}
                        </h4>
                        <div className="flex items-center gap-4">
                          <p className="text-sm text-slate-400">Link Margin:</p>
                          <p className={`text-3xl font-black ${result.margin_db > 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                            {result.margin_db > 0 ? '+' : ''}{result.margin_db.toFixed(2)} dB
                          </p>
                        </div>
                        <p className="text-[10px] text-slate-500 mt-3">
                          {result.link_viable 
                            ? 'Signal strength sufficient for reliable communication'
                            : 'Insufficient signal strength - adjust TX power, antenna gain, or reduce distance'}
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="p-6 bg-black/60 border border-white/5 rounded-2xl">
                    <h4 className="text-xs font-black text-white uppercase mb-4 flex items-center gap-2">
                      <Activity size={14} /> Recommendations
                    </h4>
                    <div className="space-y-2 text-xs text-slate-400">
                      {result.margin_db < 3 && result.margin_db > 0 && (
                        <p className="flex items-start gap-2">
                          <span className="text-yellow-400">⚠</span>
                          Link margin is minimal. Consider increasing TX power or antenna gain for reliability.
                        </p>
                      )}
                      {result.snr_db < 15 && (
                        <p className="flex items-start gap-2">
                          <span className="text-orange-400">⚠</span>
                          Low SNR may result in high bit error rate. Use forward error correction.
                        </p>
                      )}
                      {result.margin_db > 10 && (
                        <p className="flex items-start gap-2">
                          <span className="text-green-400">✓</span>
                          Excellent link margin provides robust communication even in adverse conditions.
                        </p>
                      )}
                      {(params.atmospheric_loss_db || 0) + (params.rain_loss_db || 0) > 2 && (
                        <p className="flex items-start gap-2">
                          <span className="text-blue-400">ℹ</span>
                          Significant atmospheric/rain attenuation detected. Monitor weather conditions.
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
};

export default LinkBudgetCalculator;
