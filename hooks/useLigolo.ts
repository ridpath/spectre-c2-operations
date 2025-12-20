
import { useState, useCallback, useEffect } from 'react';
import { LigoloTunnel } from '../types';

export const useLigolo = () => {
  const [tunnels, setTunnels] = useState<LigoloTunnel[]>([]);
  const [isRelayStarted, setIsRelayStarted] = useState(false);

  const startRelay = useCallback(() => {
    setIsRelayStarted(true);
  }, []);

  const stopRelay = useCallback(() => {
    setIsRelayStarted(false);
    setTunnels([]);
  }, []);

  const createTunnel = useCallback((agentId: string, remoteAddress: string) => {
    const id = `tun-${Math.random().toString(36).substr(2, 5)}`;
    const newTunnel: LigoloTunnel = {
      id,
      agentId,
      remoteAddress,
      interfaceName: `ligolo${tunnels.length}`,
      status: 'active',
      rxBytes: 0,
      txBytes: 0,
      routes: []
    };
    setTunnels(prev => [...prev, newTunnel]);
    return id;
  }, [tunnels.length]);

  const addRoute = useCallback((tunnelId: string, route: string) => {
    setTunnels(prev => prev.map(t => 
      t.id === tunnelId ? { ...t, routes: [...t.routes, route] } : t
    ));
  }, []);

  // Simulate traffic flow
  useEffect(() => {
    if (!isRelayStarted) return;
    const interval = setInterval(() => {
      setTunnels(prev => prev.map(t => ({
        ...t,
        rxBytes: t.rxBytes + Math.floor(Math.random() * 1024),
        txBytes: t.txBytes + Math.floor(Math.random() * 512)
      })));
    }, 2000);
    return () => clearInterval(interval);
  }, [isRelayStarted]);

  return {
    tunnels,
    isRelayStarted,
    startRelay,
    stopRelay,
    createTunnel,
    addRoute
  };
};
