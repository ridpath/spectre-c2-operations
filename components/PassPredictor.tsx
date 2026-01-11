import React, { useState, useEffect } from 'react';
import { Clock, Satellite, TrendingUp, AlertCircle } from 'lucide-react';
import { AOSWindow, OrbitalAsset } from '../types';
import { satelliteService } from '../services/satelliteService';
import { locationService } from '../services/locationService';

interface PassPredictorProps {
  satellite: OrbitalAsset | null;
  onPassClick?: (pass: AOSWindow) => void;
}

const PassPredictor: React.FC<PassPredictorProps> = ({ satellite, onPassClick }) => {
  const [currentPass, setCurrentPass] = useState<AOSWindow | null>(null);
  const [upcomingPasses, setUpcomingPasses] = useState<AOSWindow[]>([]);
  const [countdown, setCountdown] = useState<string>('--:--:--');
  const [timeInPass, setTimeInPass] = useState<string>('--:--');
  const [position, setPosition] = useState<{ azimuth: number; elevation: number } | null>(null);
  const [observerLocation, setObserverLocation] = useState<{ lat: number; lng: number }>({ lat: 37.7749, lng: -122.4194 });
  
  useEffect(() => {
    locationService.ensureLocation().then(coords => {
      setObserverLocation({ lat: coords.latitude, lng: coords.longitude });
    }).catch(() => {
      console.warn('Using default location');
    });
  }, []);
  
  useEffect(() => {
    if (!satellite || !satellite.tle) return;

    const observerLat = observerLocation.lat;
    const observerLng = observerLocation.lng;

    const calculatePasses = () => {
      const now = new Date();
      const passes: AOSWindow[] = [];
      const orbitPeriod = 90;
      
      for (let i = 0; i < 10; i++) {
        const passStart = new Date(now.getTime() + i * orbitPeriod * 60 * 1000);
        const passEnd = new Date(passStart.getTime() + 10 * 60 * 1000);
        const maxElev = 30 + Math.random() * 60;
        
        passes.push({
          id: `pass-${i}`,
          startTime: passStart,
          endTime: passEnd,
          maxElevation: Math.round(maxElev),
          isCurrent: false
        });
      }
      
      setUpcomingPasses(passes);
    };

    calculatePasses();

    const updatePosition = () => {
      const pos = satelliteService.calculateSatellitePosition(
        satellite.tle,
        observerLat,
        observerLng
      );
      if (pos) {
        setPosition({ azimuth: pos.azimuth, elevation: pos.elevation });
      }
    };

    updatePosition();
    const posInterval = setInterval(updatePosition, 1000);

    const checkCurrent = () => {
      const currentTime = new Date();
      const active = upcomingPasses.find(p => 
        currentTime >= p.startTime && currentTime <= p.endTime
      );
      setCurrentPass(active || null);
    };

    checkCurrent();
    const checkInterval = setInterval(checkCurrent, 1000);

    return () => {
      clearInterval(checkInterval);
      clearInterval(posInterval);
    };
  }, [satellite, upcomingPasses, observerLocation]);

  useEffect(() => {
    const updateCountdown = () => {
      if (!upcomingPasses[0]) return;

      const now = new Date();
      const nextPass = upcomingPasses[0];

      if (currentPass) {
        const elapsed = now.getTime() - currentPass.startTime.getTime();
        const total = currentPass.endTime.getTime() - currentPass.startTime.getTime();
        const remaining = total - elapsed;
        
        const mins = Math.floor(remaining / 60000);
        const secs = Math.floor((remaining % 60000) / 1000);
        setTimeInPass(`${mins}:${secs.toString().padStart(2, '0')}`);
        setCountdown('IN PASS');
      } else {
        const timeUntil = nextPass.startTime.getTime() - now.getTime();
        
        if (timeUntil < 0) {
          setCountdown('CALCULATING...');
          return;
        }

        const hours = Math.floor(timeUntil / 3600000);
        const mins = Math.floor((timeUntil % 3600000) / 60000);
        const secs = Math.floor((timeUntil % 60000) / 1000);
        
        if (hours > 0) {
          setCountdown(`${hours}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`);
        } else {
          setCountdown(`${mins}:${secs.toString().padStart(2, '0')}`);
        }
        setTimeInPass('--:--');
      }
    };

    updateCountdown();
    const interval = setInterval(updateCountdown, 1000);
    return () => clearInterval(interval);
  }, [upcomingPasses, currentPass]);

  if (!satellite) {
    return (
      <div className="bg-slate-900/40 border border-slate-800 rounded-2xl p-4">
        <div className="flex items-center gap-2 text-slate-600">
          <AlertCircle size={16} />
          <span className="text-xs font-bold uppercase">No Satellite Selected</span>
        </div>
      </div>
    );
  }

  const nextPass = upcomingPasses[0];
  const isUrgent = nextPass && (nextPass.startTime.getTime() - Date.now()) < 5 * 60 * 1000;

  return (
    <div className={`bg-slate-900/40 border rounded-2xl p-4 ${
      currentPass ? 'border-emerald-500 shadow-lg shadow-emerald-900/20' : 
      isUrgent ? 'border-yellow-500 shadow-lg shadow-yellow-900/20' : 
      'border-slate-800'
    }`}>
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Satellite size={16} className={currentPass ? 'text-emerald-500' : 'text-blue-500'} />
            <span className="text-xs font-black uppercase text-slate-400">
              {currentPass ? 'Pass Active' : 'Next Pass'}
            </span>
          </div>
          {currentPass && (
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          )}
        </div>

        <div className="space-y-2">
          <div className="flex items-baseline gap-2">
            <Clock size={20} className={currentPass ? 'text-emerald-500' : isUrgent ? 'text-yellow-500' : 'text-blue-500'} />
            <span className={`text-2xl font-black ${
              currentPass ? 'text-emerald-400' : 
              isUrgent ? 'text-yellow-400' : 
              'text-blue-400'
            }`}>
              {countdown}
            </span>
          </div>

          {currentPass && (
            <div className="text-xs text-slate-500 font-bold uppercase">
              Time Remaining in Pass: {timeInPass}
            </div>
          )}

          {nextPass && !currentPass && (
            <div className="space-y-1 text-xs text-slate-500">
              <div className="flex justify-between">
                <span className="font-bold uppercase">AOS:</span>
                <span>{nextPass.startTime.toLocaleTimeString()}</span>
              </div>
              <div className="flex justify-between">
                <span className="font-bold uppercase">Max El:</span>
                <span className="flex items-center gap-1">
                  <TrendingUp size={12} />
                  {nextPass.maxElevation}°
                </span>
              </div>
              <div className="flex justify-between">
                <span className="font-bold uppercase">Duration:</span>
                <span>
                  {Math.floor((nextPass.endTime.getTime() - nextPass.startTime.getTime()) / 60000)} min
                </span>
              </div>
            </div>
          )}
        </div>

        {isUrgent && !currentPass && (
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-2 text-yellow-400 text-xs font-bold uppercase text-center">
            Pass Starting Soon - Prepare Equipment
          </div>
        )}

        {currentPass && (
          <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-2 text-emerald-400 text-xs font-bold uppercase text-center">
            Optimal Transmission Window Active
          </div>
        )}

        {upcomingPasses.length > 1 && !currentPass && (
          <div className="pt-2 border-t border-slate-800">
            <div className="text-xs font-black uppercase text-slate-600 mb-2">
              Upcoming Passes ({upcomingPasses.length - 1} more)
            </div>
            <div className="space-y-1">
              {upcomingPasses.slice(1, 4).map((pass, idx) => (
                <button
                  key={pass.id}
                  onClick={() => onPassClick?.(pass)}
                  className="w-full flex justify-between items-center text-xs text-slate-500 hover:text-blue-400 hover:bg-slate-800/50 rounded p-1 transition-colors"
                >
                  <span>{pass.startTime.toLocaleTimeString()}</span>
                  <span className="flex items-center gap-1">
                    <TrendingUp size={10} />
                    {pass.maxElevation}°
                  </span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PassPredictor;
