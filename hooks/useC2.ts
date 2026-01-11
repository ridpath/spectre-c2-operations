
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
    isAuthEnabled: true,
    mfaRequired: false,
    sessionTimeout: 60,
    opsecThreshold: 75
  });

  useEffect(() => {
    const validateStoredToken = async () => {
      try {
        const token = localStorage.getItem('spectre_access_token');
        const userStr = localStorage.getItem('spectre_user');
        
        if (token && userStr) {
          const response = await fetch('http://localhost:8000/api/v1/auth/me', {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });
          
          if (response.ok) {
            const user = JSON.parse(userStr);
            setCurrentOperator({
              id: user.id,
              alias: user.username,
              role: user.role.toUpperCase() as 'ADMIN' | 'OPERATOR',
              status: 'active',
              lastSeen: new Date()
            });
          } else {
            console.log('Stored token invalid, clearing auth');
            localStorage.removeItem('spectre_access_token');
            localStorage.removeItem('spectre_refresh_token');
            localStorage.removeItem('spectre_user');
          }
        }
      } catch (error) {
        console.log('Token validation failed, clearing auth');
        localStorage.removeItem('spectre_access_token');
        localStorage.removeItem('spectre_refresh_token');
        localStorage.removeItem('spectre_user');
      }
    };
    
    validateStoredToken();
    
    setListeners([
      { id: 'l1', name: 'HTTP_Beacon_80', type: 'http', lhost: '10.10.14.12', lport: 80, active: true, profiles: ['ghost-stealth'] },
      { id: 'l2', name: 'Azure_Spectral_Mimic', type: 'spectrum', lhost: '52.12.11.90', lport: 443, active: true, profiles: ['office365-mimic'] }
    ]);
    
    setOperators([
      { id: 'op1', alias: 'Spectre-Lead', role: 'ADMIN', status: 'active', lastSeen: new Date() }
    ]);
  }, []);

  const login = useCallback((user: any) => {
    const op: Operator = {
      id: user.id || Math.random().toString(36).substr(2, 5),
      alias: user.username || user.alias || 'Operator',
      role: (user.role?.toUpperCase() || 'OPERATOR') as 'ADMIN' | 'OPERATOR',
      status: 'active',
      lastSeen: new Date()
    };
    setCurrentOperator(op);
    setOperators(prev => [...prev.filter(o => o.id !== op.id), op]);
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
