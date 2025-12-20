
import { useState, useCallback, useEffect } from 'react';
import { WinRMConnection, C2Task, C2Listener, AuthMethod, Operator, SecurityConfig } from '../types';

export const useC2 = () => {
  const [connections, setConnections] = useState<WinRMConnection[]>([]);
  const [activeConnectionId, setActiveConnectionId] = useState<string | null>(null);
  const [tasks, setTasks] = useState<C2Task[]>([]);
  const [listeners, setListeners] = useState<C2Listener[]>([]);
  const [operators, setOperators] = useState<Operator[]>([]);
  const [currentOperator, setCurrentOperator] = useState<Operator | null>(null);
  const [securityConfig, setSecurityConfig] = useState<SecurityConfig>({
    isAuthEnabled: false,
    mfaRequired: false,
    sessionTimeout: 60,
    // Fix: Added missing opsecThreshold to satisfy SecurityConfig interface
    opsecThreshold: 75
  });

  // Load Mock State
  useEffect(() => {
    setListeners([
      { id: 'l1', name: 'HTTP_Beacon_80', type: 'http', lhost: '10.10.14.12', lport: 80, active: true, profiles: ['ghost-stealth'] },
      { id: 'l2', name: 'Azure_Spectral_Mimic', type: 'spectrum', lhost: '52.12.11.90', lport: 443, active: true, profiles: ['office365-mimic'] }
    ]);
    
    setOperators([
      { id: 'op1', alias: 'Spectre-Lead', role: 'ADMIN', status: 'active', lastSeen: new Date() }
    ]);

    // Initial connections for demo
    addConnection({ host: 'DC01.HTB.LOCAL', username: 'Administrator', integrityLevel: 'Administrator', entropy: 45 });
    addConnection({ host: 'WS-01.HTB.LOCAL', username: 'jsmith', integrityLevel: 'User', entropy: 12 });
  }, []);

  const login = useCallback((alias: string) => {
    const op: Operator = {
      id: Math.random().toString(36).substr(2, 5),
      alias,
      role: 'OPERATOR',
      status: 'active',
      lastSeen: new Date()
    };
    setCurrentOperator(op);
    setOperators(prev => [...prev, op]);
  }, []);

  const logout = useCallback(() => setCurrentOperator(null), []);

  const addConnection = useCallback((data: Partial<WinRMConnection>) => {
    const id = `conn-${Math.random().toString(36).substr(2, 5)}`;
    // Fix: Added missing required stealthMode property and ensured spectrumMimicry is included
    const newConn: WinRMConnection = {
      id,
      host: data.host || '127.0.0.1',
      port: data.port || 5985,
      username: data.username || 'guest',
      password: data.password || '',
      useSsl: data.useSsl || false,
      authMethod: data.authMethod || AuthMethod.NTLM,
      status: 'connected',
      lastSeen: new Date(),
      agentType: 'Ghost-Overlord-Alpha',
      capabilities: ['recon-powerview', 'postex-mimikatz', 'auto-logic-v1'],
      integrityLevel: data.integrityLevel || 'User',
      entropy: data.entropy || Math.floor(Math.random() * 30),
      autonomousRules: [],
      spectrumMimicry: 'Standard',
      stealthMode: 'Normal'
    };
    setConnections(prev => [...prev, newConn]);
    setActiveConnectionId(id);
  }, []);

  const createTask = useCallback((targetId: string, command: string) => {
    const taskId = `task-${Math.random().toString(36).substr(2, 4)}`;
    const newTask: C2Task = {
      id: taskId,
      targetId,
      command,
      status: 'running',
      timestamp: new Date(),
      operatorAlias: currentOperator?.alias || 'Master'
    };
    setTasks(prev => [newTask, ...prev]);
    return taskId;
  }, [currentOperator]);

  const updateTask = useCallback((id: string, updates: Partial<C2Task>) => {
    setTasks(prev => prev.map(t => t.id === id ? { ...t, ...updates } : t));
  }, []);

  return {
    connections,
    activeConnectionId,
    setActiveConnectionId,
    tasks,
    listeners,
    setListeners,
    operators,
    currentOperator,
    securityConfig,
    setSecurityConfig,
    login,
    logout,
    addConnection,
    removeConnection: (id: string) => setConnections(prev => prev.filter(c => c.id !== id)),
    createTask,
    updateTask
  };
};
