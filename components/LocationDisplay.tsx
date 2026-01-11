import React, { useState, useEffect } from 'react';
import { MapPin, Edit3, Check, X } from 'lucide-react';
import { locationService, Coordinates } from '../services/locationService';

export default function LocationDisplay() {
  const [location, setLocation] = useState<Coordinates | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [editLat, setEditLat] = useState('');
  const [editLng, setEditLng] = useState('');

  useEffect(() => {
    const unsubscribe = locationService.subscribe((coords) => {
      setLocation(coords);
      if (coords) {
        setEditLat(coords.latitude.toFixed(4));
        setEditLng(coords.longitude.toFixed(4));
      }
    });

    locationService.ensureLocation().catch(() => {});

    return unsubscribe;
  }, []);

  const handleSave = () => {
    const lat = parseFloat(editLat);
    const lng = parseFloat(editLng);

    if (isNaN(lat) || isNaN(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180) {
      alert('Invalid coordinates. Lat: -90 to 90, Lng: -180 to 180');
      return;
    }

    locationService.setManualLocation(lat, lng);
    setIsEditing(false);
  };

  const handleCancel = () => {
    if (location) {
      setEditLat(location.latitude.toFixed(4));
      setEditLng(location.longitude.toFixed(4));
    }
    setIsEditing(false);
  };

  if (!location) {
    return (
      <div className="flex items-center gap-2 text-[9px] font-black text-slate-500 uppercase tracking-widest">
        <MapPin size={12} className="animate-pulse" />
        <span>Getting location...</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      {!isEditing ? (
        <>
          <MapPin size={12} className="text-emerald-500" />
          <div className="flex flex-col">
            <div className="text-[8px] font-black text-slate-400 uppercase tracking-widest">Ground Station</div>
            <div className="text-[9px] font-mono text-slate-300">
              {location.latitude.toFixed(4)}°N, {location.longitude.toFixed(4)}°E
            </div>
          </div>
          <button
            onClick={() => setIsEditing(true)}
            className="ml-2 p-1 rounded hover:bg-slate-800 transition-colors"
            title="Edit location"
          >
            <Edit3 size={10} className="text-slate-500 hover:text-purple-400" />
          </button>
        </>
      ) : (
        <div className="flex items-center gap-2">
          <input
            type="number"
            value={editLat}
            onChange={(e) => setEditLat(e.target.value)}
            placeholder="Latitude"
            className="w-20 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-[9px] font-mono text-slate-300 focus:outline-none focus:border-purple-500"
            step="0.0001"
            min="-90"
            max="90"
          />
          <input
            type="number"
            value={editLng}
            onChange={(e) => setEditLng(e.target.value)}
            placeholder="Longitude"
            className="w-20 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-[9px] font-mono text-slate-300 focus:outline-none focus:border-purple-500"
            step="0.0001"
            min="-180"
            max="180"
          />
          <button
            onClick={handleSave}
            className="p-1 rounded hover:bg-emerald-600 transition-colors"
            title="Save"
          >
            <Check size={12} className="text-emerald-500 hover:text-white" />
          </button>
          <button
            onClick={handleCancel}
            className="p-1 rounded hover:bg-red-600 transition-colors"
            title="Cancel"
          >
            <X size={12} className="text-red-500 hover:text-white" />
          </button>
        </div>
      )}
    </div>
  );
}
