import React, { useState, useEffect } from 'react';
import { Briefcase, Plus, Target, Clock, CheckCircle, XCircle, AlertTriangle, Play, Pause, Eye } from 'lucide-react';
import { SatelliteMission, OrbitalAsset, AOSWindow } from '../types';
import { missionService } from '../services/missionService';

interface MissionPlannerProps {
  satellites: OrbitalAsset[];
  onCreateMission: (mission: Omit<SatelliteMission, 'id' | 'createdAt' | 'evidence' | 'attackChain'>) => void;
  onSelectMission: (mission: SatelliteMission) => void;
}

const MissionPlanner: React.FC<MissionPlannerProps> = ({ satellites, onCreateMission, onSelectMission }) => {
  const [missions, setMissions] = useState<SatelliteMission[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newMission, setNewMission] = useState({
    name: '',
    targetSatellite: '',
    targetNoradId: 0,
    objective: 'recon' as const,
    hasAuthorization: false,
    authDocPath: '',
    authBy: ''
  });

  useEffect(() => {
    const loadMissions = async () => {
      const loadedMissions = await missionService.getMissions();
      setMissions(loadedMissions);
    };
    loadMissions();
  }, []);

  const getStatusColor = (status: SatelliteMission['status']) => {
    switch (status) {
      case 'planning': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      case 'waiting': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'active': return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'completed': return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
      case 'aborted': return 'text-red-400 bg-red-500/10 border-red-500/30';
    }
  };

  const getObjectiveIcon = (objective: SatelliteMission['objective']) => {
    switch (objective) {
      case 'recon': return <Eye size={14} />;
      case 'exploit': return <Target size={14} />;
      case 'persistence': return <Clock size={14} />;
      case 'eavesdrop': return <Eye size={14} />;
      default: return <AlertTriangle size={14} />;
    }
  };

  const handleCreateMission = async () => {
    const selectedSat = satellites.find(s => s.designation === newMission.targetSatellite);
    if (!selectedSat) return;

    try {
      const created = await missionService.createMission({
        name: newMission.name,
        targetSatellite: newMission.targetSatellite,
        targetNoradId: selectedSat.noradId,
        objective: newMission.objective,
        authorization: {
          hasPermission: newMission.hasAuthorization,
          documentPath: newMission.authDocPath,
          authorizedBy: newMission.authBy,
          scope: [newMission.objective]
        }
      });

      setMissions([...missions, created]);
      onCreateMission({
        name: newMission.name,
        targetSatellite: newMission.targetSatellite,
        targetNoradId: selectedSat.noradId,
        objective: newMission.objective,
        nextPass: null,
        status: 'planning',
        authorization: {
          hasPermission: newMission.hasAuthorization,
          documentPath: newMission.authDocPath,
          authorizedBy: newMission.authBy,
          scope: [newMission.objective]
        }
      });

      setShowCreateModal(false);
      setNewMission({
        name: '',
        targetSatellite: '',
        targetNoradId: 0,
        objective: 'recon',
        hasAuthorization: false,
        authDocPath: '',
        authBy: ''
      });
    } catch (error) {
      console.error('Failed to create mission:', error);
    }
  };

  return (
    <div className="h-full flex flex-col gap-6">
      <header className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-black text-emerald-400 uppercase tracking-tighter flex items-center gap-2">
            <Briefcase size={20} /> Mission Control
          </h2>
          <p className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mt-1">
            Active Satellite Penetration Testing Missions
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2.5 bg-emerald-600 hover:bg-emerald-500 rounded-xl text-white font-bold text-sm transition-all"
        >
          <Plus size={16} />
          New Mission
        </button>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 overflow-y-auto pr-2">
        {missions.map(mission => (
          <button
            key={mission.id}
            onClick={() => onSelectMission(mission)}
            className="text-left bg-slate-900/40 border border-slate-800 hover:border-emerald-500/50 rounded-2xl p-6 transition-all group"
          >
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  {getObjectiveIcon(mission.objective)}
                  <h3 className="text-lg font-black text-slate-300 group-hover:text-emerald-400 transition-colors">
                    {mission.name}
                  </h3>
                </div>
                <div className="text-xs text-slate-500 font-mono">
                  {mission.targetSatellite} (NORAD {mission.targetNoradId})
                </div>
              </div>
              <div className={`text-[10px] font-black uppercase px-2 py-1 rounded-lg border ${getStatusColor(mission.status)}`}>
                {mission.status}
              </div>
            </div>

            <div className="space-y-2 mb-4">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-600 uppercase font-bold">Objective:</span>
                <span className="text-blue-400 uppercase">{mission.objective}</span>
              </div>
              {mission.nextPass && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 uppercase font-bold">Next Pass:</span>
                  <span className="text-yellow-400">
                    {Math.floor((mission.nextPass.startTime.getTime() - Date.now()) / 60000)} min
                  </span>
                </div>
              )}
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-600 uppercase font-bold">Evidence:</span>
                <span className="text-slate-400">{mission.evidence.length} items</span>
              </div>
            </div>

            <div className="flex items-center gap-2 pt-3 border-t border-slate-800">
              {mission.authorization.hasPermission ? (
                <div className="flex items-center gap-1 text-emerald-400 text-xs">
                  <CheckCircle size={12} />
                  <span>Authorized</span>
                </div>
              ) : (
                <div className="flex items-center gap-1 text-red-400 text-xs">
                  <XCircle size={12} />
                  <span>No Authorization</span>
                </div>
              )}
              {mission.status === 'active' && (
                <div className="flex items-center gap-1 text-emerald-400 text-xs ml-auto">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span>In Progress</span>
                </div>
              )}
            </div>
          </button>
        ))}

        {missions.length === 0 && (
          <div className="col-span-2 text-center py-20 text-slate-600">
            <Briefcase size={60} className="mx-auto mb-4 opacity-20" />
            <div className="text-lg font-bold uppercase mb-2">No Active Missions</div>
            <div className="text-sm">Create a new mission to begin satellite pentesting operations</div>
          </div>
        )}
      </div>

      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-3xl max-w-2xl w-full p-8">
            <h3 className="text-xl font-black text-emerald-400 uppercase mb-6">Create New Mission</h3>
            
            <div className="space-y-4 mb-6">
              <div>
                <label className="text-xs font-bold text-slate-400 uppercase mb-2 block">Mission Name</label>
                <input
                  type="text"
                  value={newMission.name}
                  onChange={(e) => setNewMission({ ...newMission, name: e.target.value })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-300 outline-none focus:border-emerald-500 transition-all"
                  placeholder="e.g., NOAA-15 Telemetry Analysis"
                />
              </div>

              <div>
                <label className="text-xs font-bold text-slate-400 uppercase mb-2 block">Target Satellite</label>
                <select
                  value={newMission.targetSatellite}
                  onChange={(e) => setNewMission({ ...newMission, targetSatellite: e.target.value })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-300 outline-none focus:border-emerald-500 transition-all"
                >
                  <option value="">Select satellite...</option>
                  {satellites.map(sat => (
                    <option key={sat.id} value={sat.designation}>
                      {sat.designation} (NORAD {sat.noradId})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs font-bold text-slate-400 uppercase mb-2 block">Objective</label>
                <select
                  value={newMission.objective}
                  onChange={(e) => setNewMission({ ...newMission, objective: e.target.value as any })}
                  className="w-full bg-black/40 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-300 outline-none focus:border-emerald-500 transition-all"
                >
                  <option value="recon">Reconnaissance</option>
                  <option value="exploit">Exploitation</option>
                  <option value="persistence">Persistence</option>
                  <option value="eavesdrop">Eavesdropping</option>
                  <option value="hijack">Hijacking</option>
                  <option value="dos">Denial of Service</option>
                </select>
              </div>

              <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4">
                <div className="flex items-start gap-2 mb-3">
                  <AlertTriangle size={16} className="text-yellow-500 shrink-0 mt-0.5" />
                  <div className="text-xs font-bold text-yellow-400 uppercase">Authorization Required</div>
                </div>
                <div className="space-y-3">
                  <label className="flex items-center gap-2 text-sm text-slate-300">
                    <input
                      type="checkbox"
                      checked={newMission.hasAuthorization}
                      onChange={(e) => setNewMission({ ...newMission, hasAuthorization: e.target.checked })}
                      className="accent-emerald-500"
                    />
                    I have written authorization for this operation
                  </label>
                  {newMission.hasAuthorization && (
                    <>
                      <input
                        type="text"
                        placeholder="Authorization document path"
                        value={newMission.authDocPath}
                        onChange={(e) => setNewMission({ ...newMission, authDocPath: e.target.value })}
                        className="w-full bg-black/40 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 outline-none focus:border-emerald-500"
                      />
                      <input
                        type="text"
                        placeholder="Authorized by"
                        value={newMission.authBy}
                        onChange={(e) => setNewMission({ ...newMission, authBy: e.target.value })}
                        className="w-full bg-black/40 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 outline-none focus:border-emerald-500"
                      />
                    </>
                  )}
                </div>
              </div>
            </div>

            <div className="flex gap-3">
              <button
                onClick={() => setShowCreateModal(false)}
                className="flex-1 py-3 bg-slate-800 hover:bg-slate-700 rounded-xl text-white font-bold text-sm transition-all"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateMission}
                disabled={!newMission.name || !newMission.targetSatellite || !newMission.hasAuthorization}
                className={`flex-1 py-3 rounded-xl font-bold text-sm transition-all ${
                  newMission.name && newMission.targetSatellite && newMission.hasAuthorization
                    ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                    : 'bg-slate-800 text-slate-600 cursor-not-allowed'
                }`}
              >
                Create Mission
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MissionPlanner;
