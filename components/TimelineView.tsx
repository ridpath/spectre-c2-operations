import React, { useState, useEffect } from 'react';
import { Calendar, Clock, Satellite, TrendingUp } from 'lucide-react';
import { AOSWindow, OrbitalAsset } from '../types';

interface TimelineViewProps {
  satellites: OrbitalAsset[];
  onPassSelect: (pass: AOSWindow, satellite: OrbitalAsset) => void;
}

const TimelineView: React.FC<TimelineViewProps> = ({ satellites, onPassSelect }) => {
  const [passes, setPasses] = useState<Array<{ satellite: OrbitalAsset; pass: AOSWindow }>>([]);
  const [timeRange, setTimeRange] = useState(24);

  useEffect(() => {
    generatePasses();
  }, [satellites, timeRange]);

  const generatePasses = () => {
    const now = new Date();
    const allPasses: Array<{ satellite: OrbitalAsset; pass: AOSWindow }> = [];

    satellites.forEach(sat => {
      for (let i = 0; i < 10; i++) {
        const passStart = new Date(now.getTime() + (i * 95 * 60 * 1000) + (Math.random() * 30 * 60 * 1000));
        const duration = 8 + Math.random() * 5;
        const passEnd = new Date(passStart.getTime() + duration * 60 * 1000);
        
        if (passStart.getTime() - now.getTime() <= timeRange * 60 * 60 * 1000) {
          allPasses.push({
            satellite: sat,
            pass: {
              id: `pass-${sat.id}-${i}`,
              startTime: passStart,
              endTime: passEnd,
              maxElevation: 20 + Math.random() * 70,
              isCurrent: false
            }
          });
        }
      }
    });

    allPasses.sort((a, b) => a.pass.startTime.getTime() - b.pass.startTime.getTime());
    setPasses(allPasses);
  };

  const getPassQuality = (elevation: number) => {
    if (elevation >= 60) return { quality: 'excellent', color: 'emerald' };
    if (elevation >= 45) return { quality: 'good', color: 'blue' };
    if (elevation >= 30) return { quality: 'fair', color: 'yellow' };
    return { quality: 'poor', color: 'red' };
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  };

  const formatDuration = (start: Date, end: Date) => {
    const mins = Math.floor((end.getTime() - start.getTime()) / 60000);
    return `${mins}m`;
  };

  const getTimeUntil = (date: Date) => {
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    if (diff < 0) return 'In Progress';
    
    const hours = Math.floor(diff / 3600000);
    const mins = Math.floor((diff % 3600000) / 60000);
    
    if (hours > 0) return `${hours}h ${mins}m`;
    return `${mins}m`;
  };

  const isUpcoming = (pass: AOSWindow) => {
    const now = new Date();
    const timeUntil = pass.startTime.getTime() - now.getTime();
    return timeUntil > 0 && timeUntil < 30 * 60 * 1000;
  };

  const hourBlocks = Array.from({ length: timeRange }, (_, i) => i);

  return (
    <div className="h-full flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
            <Calendar size={20} /> Pass Timeline
          </h2>
          <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">
            Upcoming Satellite Passes ({passes.length} scheduled)
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setTimeRange(12)}
            className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${
              timeRange === 12
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            12h
          </button>
          <button
            onClick={() => setTimeRange(24)}
            className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${
              timeRange === 24
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            24h
          </button>
          <button
            onClick={() => setTimeRange(48)}
            className={`px-4 py-2 rounded-xl text-xs font-bold uppercase transition-all ${
              timeRange === 48
                ? 'bg-emerald-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-white'
            }`}
          >
            48h
          </button>
        </div>
      </header>

      <div className="flex gap-4 text-xs">
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-emerald-500/30 border border-emerald-500/50"></div>
          <span className="text-slate-500">Excellent (&gt;60°)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-blue-500/30 border border-blue-500/50"></div>
          <span className="text-slate-500">Good (45-60°)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-yellow-500/30 border border-yellow-500/50"></div>
          <span className="text-slate-500">Fair (30-45°)</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded bg-red-500/30 border border-red-500/50"></div>
          <span className="text-slate-500">Poor (&lt;30°)</span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto space-y-3 pr-2">
        {passes.map((item, idx) => {
          const { quality, color } = getPassQuality(item.pass.maxElevation);
          const upcoming = isUpcoming(item.pass);
          
          return (
            <button
              key={item.pass.id}
              onClick={() => onPassSelect(item.pass, item.satellite)}
              className={`w-full text-left bg-slate-900/40 border rounded-2xl p-4 transition-all hover:border-emerald-500/50 ${
                upcoming ? 'border-yellow-500 shadow-lg shadow-yellow-900/20' : 'border-slate-800'
              }`}
            >
              <div className="flex items-start justify-between gap-4 mb-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <Satellite size={14} className={`text-${color}-500`} />
                    <span className="text-sm font-black text-slate-300">{item.satellite.designation}</span>
                    {upcoming && (
                      <span className="text-[10px] font-black uppercase px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400">
                        Soon
                      </span>
                    )}
                  </div>
                  <div className="text-xs text-slate-600 font-mono">NORAD {item.satellite.noradId}</div>
                </div>
                <div className={`text-[10px] font-black uppercase px-2 py-1 rounded-lg border bg-${color}-500/10 text-${color}-400 border-${color}-500/30`}>
                  {quality}
                </div>
              </div>

              <div className="grid grid-cols-4 gap-4 text-xs mb-3">
                <div>
                  <div className="text-slate-600 uppercase font-bold mb-1">AOS</div>
                  <div className="text-slate-300 font-mono">{formatTime(item.pass.startTime)}</div>
                </div>
                <div>
                  <div className="text-slate-600 uppercase font-bold mb-1">LOS</div>
                  <div className="text-slate-300 font-mono">{formatTime(item.pass.endTime)}</div>
                </div>
                <div>
                  <div className="text-slate-600 uppercase font-bold mb-1">Max El</div>
                  <div className={`text-${color}-400 font-mono flex items-center gap-1`}>
                    <TrendingUp size={10} />
                    {item.pass.maxElevation.toFixed(0)}°
                  </div>
                </div>
                <div>
                  <div className="text-slate-600 uppercase font-bold mb-1">Duration</div>
                  <div className="text-slate-300 font-mono">{formatDuration(item.pass.startTime, item.pass.endTime)}</div>
                </div>
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-slate-800">
                <div className="flex items-center gap-2 text-xs">
                  <Clock size={12} className={upcoming ? 'text-yellow-400' : 'text-slate-600'} />
                  <span className={upcoming ? 'text-yellow-400 font-bold' : 'text-slate-500'}>
                    {getTimeUntil(item.pass.startTime)}
                  </span>
                </div>
                <div className="text-xs text-blue-400 font-bold uppercase">Click to Plan</div>
              </div>

              <div className="mt-3 bg-slate-950 border border-slate-800 rounded-xl p-2">
                <div className="h-8 flex items-end gap-0.5">
                  {Array.from({ length: 20 }).map((_, i) => {
                    const progress = i / 20;
                    const elevation = Math.sin(progress * Math.PI) * item.pass.maxElevation;
                    const height = (elevation / 90) * 100;
                    return (
                      <div
                        key={i}
                        className={`flex-1 bg-${color}-500/50 rounded-t`}
                        style={{ height: `${height}%` }}
                      />
                    );
                  })}
                </div>
              </div>
            </button>
          );
        })}

        {passes.length === 0 && (
          <div className="text-center py-20 text-slate-600">
            <Calendar size={60} className="mx-auto mb-4 opacity-20" />
            <div className="text-lg font-bold uppercase mb-2">No Passes Scheduled</div>
            <div className="text-sm">No satellite passes in the next {timeRange} hours</div>
          </div>
        )}
      </div>
    </div>
  );
};

export default TimelineView;
