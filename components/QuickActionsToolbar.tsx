import React, { useEffect } from 'react';
import { Target, Radio, Send, Database, AlertCircle, Zap, Eye, Settings } from 'lucide-react';

interface QuickAction {
  id: string;
  icon: React.ReactNode;
  label: string;
  hotkey: string;
  action: () => void;
  disabled?: boolean;
  danger?: boolean;
}

interface QuickActionsToolbarProps {
  onStartTracking: () => void;
  onMonitorSignal: () => void;
  onInjectPacket: () => void;
  onRecordIQ: () => void;
  onEmergencyStop: () => void;
  onShowSettings: () => void;
  inPass: boolean;
  recording: boolean;
}

const QuickActionsToolbar: React.FC<QuickActionsToolbarProps> = ({
  onStartTracking,
  onMonitorSignal,
  onInjectPacket,
  onRecordIQ,
  onEmergencyStop,
  onShowSettings,
  inPass,
  recording
}) => {
  const actions: QuickAction[] = [
    {
      id: 'track',
      icon: <Target size={16} />,
      label: 'Start Tracking',
      hotkey: 'Ctrl+T',
      action: onStartTracking
    },
    {
      id: 'monitor',
      icon: <Radio size={16} />,
      label: 'Monitor Signal',
      hotkey: 'Ctrl+M',
      action: onMonitorSignal
    },
    {
      id: 'inject',
      icon: <Send size={16} />,
      label: 'Inject Packet',
      hotkey: 'Ctrl+I',
      action: onInjectPacket,
      disabled: !inPass,
      danger: true
    },
    {
      id: 'record',
      icon: <Database size={16} />,
      label: recording ? 'Stop Recording' : 'Record IQ',
      hotkey: 'Ctrl+R',
      action: onRecordIQ
    },
    {
      id: 'settings',
      icon: <Settings size={16} />,
      label: 'Settings',
      hotkey: 'Ctrl+,',
      action: onShowSettings
    },
    {
      id: 'emergency',
      icon: <AlertCircle size={16} />,
      label: 'Emergency Stop',
      hotkey: 'Esc',
      action: onEmergencyStop,
      danger: true
    }
  ];

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onEmergencyStop();
        return;
      }

      if (e.ctrlKey || e.metaKey) {
        switch (e.key.toLowerCase()) {
          case 't':
            e.preventDefault();
            onStartTracking();
            break;
          case 'm':
            e.preventDefault();
            onMonitorSignal();
            break;
          case 'i':
            if (inPass) {
              e.preventDefault();
              onInjectPacket();
            }
            break;
          case 'r':
            e.preventDefault();
            onRecordIQ();
            break;
          case ',':
            e.preventDefault();
            onShowSettings();
            break;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [inPass, onStartTracking, onMonitorSignal, onInjectPacket, onRecordIQ, onEmergencyStop, onShowSettings]);

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-40">
      <div className="bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl p-3 flex items-center gap-2">
        {actions.map(action => (
          <button
            key={action.id}
            onClick={action.action}
            disabled={action.disabled}
            className={`group relative flex items-center gap-2 px-4 py-2.5 rounded-xl font-bold text-sm transition-all ${
              action.disabled
                ? 'bg-slate-800 text-slate-600 cursor-not-allowed'
                : action.danger
                ? 'bg-red-600/20 text-red-400 hover:bg-red-600 hover:text-white border border-red-500/30'
                : 'bg-emerald-600/20 text-emerald-400 hover:bg-emerald-600 hover:text-white border border-emerald-500/30'
            }`}
            title={`${action.label} (${action.hotkey})`}
          >
            {action.icon}
            <span className="hidden lg:inline">{action.label}</span>
            
            <div className="absolute -top-12 left-1/2 -translate-x-1/2 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none">
              <div className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs whitespace-nowrap shadow-xl">
                <div className="font-bold text-white">{action.label}</div>
                <div className="text-slate-500 text-[10px] mt-0.5">{action.hotkey}</div>
              </div>
            </div>
          </button>
        ))}
      </div>

      <div className="text-center mt-2 text-[10px] text-slate-600 uppercase font-bold">
        Press F1 for Help
      </div>
    </div>
  );
};

export default QuickActionsToolbar;
