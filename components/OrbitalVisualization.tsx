import React, { useEffect, useRef, useState } from 'react';
import { satelliteService } from '../services/satelliteService';
import { OrbitalAsset } from '../types';

interface OrbitalVisualizationProps {
  satellites: OrbitalAsset[];
  selectedSatellite?: string | null;
  onSelectSatellite?: (id: string) => void;
  observerLat?: number;
  observerLng?: number;
}

export default function OrbitalVisualization({
  satellites,
  selectedSatellite,
  onSelectSatellite,
  observerLat = 0,
  observerLng = 0
}: OrbitalVisualizationProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [rotation, setRotation] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [lastMouse, setLastMouse] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1.0);
  const animationRef = useRef<number | undefined>(undefined);

  const latLngToXYZ = (lat: number, lng: number, alt: number, radius: number): [number, number, number] => {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lng + 180) * (Math.PI / 180);
    const r = radius + alt / 100;
    
    const x = r * Math.sin(phi) * Math.cos(theta);
    const y = r * Math.cos(phi);
    const z = r * Math.sin(phi) * Math.sin(theta);
    
    return [x, y, z];
  };

  const project3D = (x: number, y: number, z: number, width: number, height: number): [number, number, number] => {
    const rotX = rotation.x * (Math.PI / 180);
    const rotY = rotation.y * (Math.PI / 180);
    
    let tempY = y * Math.cos(rotX) - z * Math.sin(rotX);
    let tempZ = y * Math.sin(rotX) + z * Math.cos(rotX);
    y = tempY;
    z = tempZ;
    
    let tempX = x * Math.cos(rotY) - z * Math.sin(rotY);
    tempZ = x * Math.sin(rotY) + z * Math.cos(rotY);
    x = tempX;
    z = tempZ;
    
    const perspective = 500;
    const scale = (perspective / (perspective + z)) * zoom;
    
    const x2d = x * scale + width / 2;
    const y2d = y * scale + height / 2;
    
    return [x2d, y2d, z];
  };

  const drawGlobe = (ctx: CanvasRenderingContext2D, width: number, height: number) => {
    const radius = 180;
    const centerX = width / 2;
    const centerY = height / 2;

    ctx.save();
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius * zoom, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(10, 20, 40, 0.9)';
    ctx.fill();
    ctx.strokeStyle = 'rgba(16, 185, 129, 0.3)';
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.strokeStyle = 'rgba(16, 185, 129, 0.1)';
    ctx.lineWidth = 1;
    for (let lat = -80; lat <= 80; lat += 20) {
      ctx.beginPath();
      for (let lng = -180; lng <= 180; lng += 5) {
        const [x, y, z] = latLngToXYZ(lat, lng, 0, radius);
        const [x2d, y2d] = project3D(x, y, z, width, height);
        
        if (lng === -180) {
          ctx.moveTo(x2d, y2d);
        } else {
          ctx.lineTo(x2d, y2d);
        }
      }
      ctx.stroke();
    }

    for (let lng = -180; lng <= 180; lng += 30) {
      ctx.beginPath();
      for (let lat = -90; lat <= 90; lat += 5) {
        const [x, y, z] = latLngToXYZ(lat, lng, 0, radius);
        const [x2d, y2d] = project3D(x, y, z, width, height);
        
        if (lat === -90) {
          ctx.moveTo(x2d, y2d);
        } else {
          ctx.lineTo(x2d, y2d);
        }
      }
      ctx.stroke();
    }

    ctx.restore();
  };

  const drawOrbit = (ctx: CanvasRenderingContext2D, satellite: OrbitalAsset, width: number, height: number) => {
    if (!satellite.tle) return;

    const radius = 180;
    const points: [number, number, number][] = [];
    const numPoints = 64;

    for (let i = 0; i < numPoints; i++) {
      const futureTime = new Date(Date.now() + (i * 90 * 60 * 1000 / numPoints));
      const pos = satelliteService.propagateTLE(satellite.tle, futureTime);
      
      if (pos) {
        const [x, y, z] = latLngToXYZ(pos.latitude, pos.longitude, pos.altitude, radius);
        points.push([x, y, z]);
      }
    }

    if (points.length < 2) return;

    ctx.save();
    ctx.strokeStyle = selectedSatellite === satellite.id 
      ? 'rgba(16, 185, 129, 0.6)' 
      : 'rgba(16, 185, 129, 0.2)';
    ctx.lineWidth = selectedSatellite === satellite.id ? 2 : 1;
    ctx.beginPath();

    points.forEach((point, idx) => {
      const [x2d, y2d] = project3D(point[0], point[1], point[2], width, height);
      if (idx === 0) {
        ctx.moveTo(x2d, y2d);
      } else {
        ctx.lineTo(x2d, y2d);
      }
    });

    ctx.stroke();
    ctx.restore();
  };

  const drawSatellite = (ctx: CanvasRenderingContext2D, satellite: OrbitalAsset, width: number, height: number) => {
    const radius = 180;
    const coords = satellite.coords;
    
    const [x, y, z] = latLngToXYZ(coords.lat, coords.lng, coords.alt, radius);
    const [x2d, y2d, depth] = project3D(x, y, z, width, height);

    const isSelected = selectedSatellite === satellite.id;
    const size = isSelected ? 10 : 6;

    ctx.save();
    ctx.beginPath();
    ctx.arc(x2d, y2d, size, 0, Math.PI * 2);
    ctx.fillStyle = isSelected ? '#10b981' : satellite.status === 'tracking' ? '#10b981' : '#6b7280';
    ctx.fill();
    ctx.strokeStyle = isSelected ? '#fff' : 'rgba(255, 255, 255, 0.5)';
    ctx.lineWidth = isSelected ? 2 : 1;
    ctx.stroke();

    if (depth > -50 || isSelected) {
      ctx.font = isSelected ? 'bold 12px monospace' : '10px monospace';
      ctx.fillStyle = isSelected ? '#10b981' : '#6b7280';
      ctx.textAlign = 'center';
      ctx.fillText(satellite.designation, x2d, y2d - (size + 8));
    }

    ctx.restore();
  };

  const animate = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);
    ctx.fillStyle = 'rgba(0, 0, 0, 0)';
    ctx.fillRect(0, 0, width, height);

    drawGlobe(ctx, width, height);

    satellites.forEach(sat => {
      if (sat.tle) {
        const position = satelliteService.propagateTLE(sat.tle);
        if (position) {
          sat.coords = {
            lat: position.latitude,
            lng: position.longitude,
            alt: position.altitude,
            velocity: sat.coords.velocity || 7.5
          };
        }
      }
    });

    satellites.forEach(sat => {
      drawOrbit(ctx, sat, width, height);
    });

    satellites.forEach(sat => {
      drawSatellite(ctx, sat, width, height);
    });

    if (!isDragging) {
      setRotation(prev => ({ ...prev, y: (prev.y + 0.1) % 360 }));
    }

    animationRef.current = requestAnimationFrame(animate);
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const resizeCanvas = () => {
      const container = canvas.parentElement;
      if (container) {
        canvas.width = container.clientWidth;
        canvas.height = container.clientHeight;
      }
    };

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    animationRef.current = requestAnimationFrame(animate);

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [satellites, rotation, zoom, selectedSatellite, isDragging]);

  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    setIsDragging(true);
    setLastMouse({ x: e.clientX, y: e.clientY });
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!isDragging) return;

    const dx = e.clientX - lastMouse.x;
    const dy = e.clientY - lastMouse.y;

    setRotation(prev => ({
      x: (prev.x - dy * 0.5) % 360,
      y: (prev.y + dx * 0.5) % 360
    }));

    setLastMouse({ x: e.clientX, y: e.clientY });
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(prev => Math.max(0.5, Math.min(2.0, prev * delta)));
  };

  const handleClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!onSelectSatellite || !canvasRef.current) return;

    const rect = canvasRef.current.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;
    const radius = 180;

    for (const sat of satellites) {
      const [x, y, z] = latLngToXYZ(sat.coords.lat, sat.coords.lng, sat.coords.alt, radius);
      const [x2d, y2d] = project3D(x, y, z, canvasRef.current.width, canvasRef.current.height);

      const distance = Math.sqrt((clickX - x2d) ** 2 + (clickY - y2d) ** 2);
      if (distance < 15) {
        onSelectSatellite(sat.id);
        return;
      }
    }
  };

  return (
    <div className="relative w-full h-full bg-black/20 rounded-lg border border-green-500/20">
      <canvas
        ref={canvasRef}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
        onClick={handleClick}
        className="w-full h-full cursor-grab active:cursor-grabbing"
        style={{ touchAction: 'none' }}
      />
      
      <div className="absolute top-4 right-4 bg-black/80 border border-green-500/30 rounded px-3 py-2 text-xs font-mono">
        <div className="text-green-400">Satellites: {satellites.length}</div>
        <div className="text-green-400/60 mt-1">Drag: Rotate | Scroll: Zoom</div>
      </div>
    </div>
  );
}
