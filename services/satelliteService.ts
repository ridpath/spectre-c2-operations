import { OrbitalAsset } from '../types';
import * as satellite from 'satellite.js';

const BACKEND_URL = 'http://localhost:8000/api/v1';

interface TLEData {
  name: string;
  line1: string;
  line2: string;
  noradId: number;
}

interface SatelliteData {
  id: string;
  norad_id: number;
  name: string;
  tle_line1: string;
  tle_line2: string;
  altitude_km?: number;
  inclination_deg?: number;
  classification?: string;
  created_at?: string;
  epoch?: string;
  source?: string;
}

class SatelliteService {
  private tleCache: Map<number, TLEData> = new Map();
  private lastFetch: number = 0;
  private cacheDuration = 3600000;

  private getAuthHeaders(): HeadersInit {
    const token = localStorage.getItem('spectre_access_token');
    return {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : '',
    };
  }

  async fetchSatellitesFromBackend(limit: number = 100, constellation?: string): Promise<SatelliteData[]> {
    try {
      let url = `${BACKEND_URL}/satellites/list?limit=${limit}`;
      if (constellation) {
        url += `&constellation=${encodeURIComponent(constellation)}`;
      }

      const response = await fetch(url, {
        headers: this.getAuthHeaders(),
      });
      
      if (!response.ok) {
        console.warn('Backend satellite fetch failed');
        return [];
      }

      const data = await response.json();
      return data.satellites || [];
    } catch (error) {
      console.error('Error fetching satellites from backend:', error);
      return [];
    }
  }

  async triggerSatelliteFetch(sources: string[] = ['celestrak', 'spacetrack']): Promise<{ success: boolean; message: string; count?: number }> {
    try {
      const token = localStorage.getItem('spectre_access_token');
      if (!token) {
        console.warn('No authentication token available, skipping satellite fetch');
        return { success: false, message: 'Authentication required' };
      }

      const response = await fetch(`${BACKEND_URL}/satellites/fetch-all`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ sources }),
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          console.warn('Authentication failed for satellite fetch');
          return { success: false, message: 'Authentication required' };
        }
        const errorText = await response.text();
        console.error(`Satellite fetch failed (${response.status}):`, errorText);
        try {
          const error = JSON.parse(errorText);
          return { success: false, message: error.detail || error.message || 'Fetch failed' };
        } catch {
          return { success: false, message: errorText || 'Fetch failed' };
        }
      }

      return await response.json();
    } catch (error) {
      console.error('Error triggering satellite fetch:', error);
      return { success: false, message: `Network error: ${error instanceof Error ? error.message : 'Unknown'}` };
    }
  }

  async fetchTLEFromCelestrak(noradIds: number[]): Promise<Map<number, TLEData>> {
    try {
      const response = await fetch(`https://celestrak.org/NORAD/elements/gp.php?CATNR=${noradIds.join(',')}&FORMAT=TLE`);
      
      if (!response.ok) {
        console.warn('Celestrak fetch failed, using cached/mock data');
        return this.tleCache;
      }

      const text = await response.text();
      const lines = text.trim().split('\n');
      const tleMap = new Map<number, TLEData>();

      for (let i = 0; i < lines.length; i += 3) {
        if (i + 2 >= lines.length) break;

        const name = lines[i].trim();
        const line1 = lines[i + 1].trim();
        const line2 = lines[i + 2].trim();

        const noradIdMatch = line1.match(/^1\s+(\d+)U/);
        if (noradIdMatch) {
          const noradId = parseInt(noradIdMatch[1], 10);
          tleMap.set(noradId, { name, line1, line2, noradId });
        }
      }

      this.tleCache = tleMap;
      this.lastFetch = Date.now();
      return tleMap;
    } catch (error) {
      console.error('Error fetching TLE data from Celestrak:', error);
      return this.tleCache;
    }
  }

  async updateOrbitalAssets(assets: OrbitalAsset[]): Promise<OrbitalAsset[]> {
    const now = Date.now();
    const shouldRefetch = now - this.lastFetch > this.cacheDuration || this.tleCache.size === 0;

    if (shouldRefetch) {
      const noradIds = assets.map(sat => sat.noradId);
      await this.fetchTLEFromCelestrak(noradIds);
    }

    return assets.map(asset => {
      const tleData = this.tleCache.get(asset.noradId);
      if (tleData) {
        return {
          ...asset,
          tle: {
            line1: tleData.line1,
            line2: tleData.line2,
            epoch: new Date().toISOString()
          }
        };
      }
      return asset;
    });
  }

  calculateSatellitePosition(tle: { line1: string; line2: string }, observerLat: number = 0, observerLng: number = 0, observerAlt: number = 0): {
    azimuth: number;
    elevation: number;
    range: number;
    latitude: number;
    longitude: number;
    altitude: number;
    velocity: number;
  } | null {
    try {
      const satrec = satellite.twoline2satrec(tle.line1, tle.line2);
      const now = new Date();
      
      const positionAndVelocity = satellite.propagate(satrec, now);
      
      if (!positionAndVelocity.position || typeof positionAndVelocity.position === 'boolean') {
        return null;
      }

      const positionEci = positionAndVelocity.position;
      const gmst = satellite.gstime(now);
      const positionGd = satellite.eciToGeodetic(positionEci, gmst);
      
      const longitude = satellite.degreesLong(positionGd.longitude);
      const latitude = satellite.degreesLat(positionGd.latitude);
      const altitude = positionGd.height;

      const observerGd = {
        latitude: observerLat * (Math.PI / 180),
        longitude: observerLng * (Math.PI / 180),
        height: observerAlt / 1000
      };

      const positionEcf = satellite.eciToEcf(positionEci, gmst);
      const lookAngles = satellite.ecfToLookAngles(observerGd, positionEcf);

      const velocity = (positionAndVelocity && positionAndVelocity.velocity && typeof positionAndVelocity.velocity !== 'boolean')
        ? Math.sqrt(
            (positionAndVelocity.velocity.x ?? 0) ** 2 +
            (positionAndVelocity.velocity.y ?? 0) ** 2 +
            (positionAndVelocity.velocity.z ?? 0) ** 2
          )
        : 7.5;

      return {
        azimuth: lookAngles.azimuth * (180 / Math.PI),
        elevation: lookAngles.elevation * (180 / Math.PI),
        range: lookAngles.rangeSat,
        latitude,
        longitude,
        altitude,
        velocity
      };
    } catch (error) {
      console.error('Error calculating satellite position:', error);
      return null;
    }
  }

  propagateTLE(tle: { line1: string; line2: string }, date?: Date): {
    latitude: number;
    longitude: number;
    altitude: number;
  } | null {
    try {
      const satrec = satellite.twoline2satrec(tle.line1, tle.line2);
      const positionAndVelocity = satellite.propagate(satrec, date || new Date());
      
      if (!positionAndVelocity.position || typeof positionAndVelocity.position === 'boolean') {
        return null;
      }

      const gmst = satellite.gstime(date || new Date());
      const positionGd = satellite.eciToGeodetic(positionAndVelocity.position as any, gmst);
      
      return {
        longitude: satellite.degreesLong(positionGd.longitude),
        latitude: satellite.degreesLat(positionGd.latitude),
        altitude: positionGd.height
      };
    } catch (error) {
      console.error('Error propagating TLE:', error);
      return null;
    }
  }

  isSatelliteOverhead(tle: { line1: string; line2: string }, observerLat: number, observerLng: number, minElevation: number = 0): boolean {
    const position = this.calculateSatellitePosition(tle, observerLat, observerLng);
    return position ? position.elevation > minElevation : false;
  }

  filterByConstellation(satellites: any[], constellation: string): any[] {
    const patterns: Record<string, string[]> = {
      'starlink': ['STARLINK'],
      'iridium': ['IRIDIUM'],
      'oneweb': ['ONEWEB'],
      'weather': ['NOAA', 'METEOR', 'FENGYUN', 'METOP'],
      'gps': ['NAVSTAR', 'GPS'],
      'galileo': ['GALILEO', 'GSAT'],
      'glonass': ['COSMOS'],
      'amateur': ['AO-', 'SO-', 'FO-', 'XW-', 'FUNCUBE', 'CUBESAT'],
      'iss': ['ISS', 'ZARYA'],
      'scientific': ['HUBBLE', 'CHANDRA', 'SWIFT', 'FERMI', 'TESS'],
      'imaging': ['LANDSAT', 'SENTINEL', 'WORLDVIEW', 'PLANET']
    };

    if (constellation === 'all') {
      return satellites;
    }

    const searchTerms = patterns[constellation.toLowerCase()] || [constellation.toUpperCase()];
    
    return satellites.filter(sat => {
      const name = sat.designation || sat.name || '';
      return searchTerms.some(term => name.toUpperCase().includes(term));
    });
  }

  filterOverheadSatellites(satellites: any[], observerLat: number, observerLng: number, minElevation: number = 10): any[] {
    return satellites.filter(sat => {
      if (!sat.tle) return false;
      return this.isSatelliteOverhead(sat.tle, observerLat, observerLng, minElevation);
    });
  }

  async fetchActiveSatellites(group: string = 'active'): Promise<TLEData[]> {
    try {
      const response = await fetch(`https://celestrak.org/NORAD/elements/gp.php?GROUP=${group}&FORMAT=TLE`);
      
      if (!response.ok) {
        console.warn('Celestrak group fetch failed');
        return [];
      }

      const text = await response.text();
      const lines = text.trim().split('\n');
      const satellites: TLEData[] = [];

      for (let i = 0; i < lines.length; i += 3) {
        if (i + 2 >= lines.length) break;

        const name = lines[i].trim();
        const line1 = lines[i + 1].trim();
        const line2 = lines[i + 2].trim();

        const noradIdMatch = line1.match(/^1\s+(\d+)U/);
        if (noradIdMatch) {
          const noradId = parseInt(noradIdMatch[1], 10);
          satellites.push({ name, line1, line2, noradId });
        }
      }

      return satellites;
    } catch (error) {
      console.error('Error fetching satellite group from Celestrak:', error);
      return [];
    }
  }

  convertToOrbitalAsset(satData: SatelliteData): OrbitalAsset | null {
    try {
      const position = this.propagateTLE({
        line1: satData.tle_line1,
        line2: satData.tle_line2
      });

      if (!position) {
        console.warn(`Failed to propagate TLE for ${satData.name} (NORAD: ${satData.norad_id})`);
        return null;
      }

      return {
        id: satData.id,
        designation: satData.name,
        noradId: satData.norad_id,
        type: position.altitude < 2000 ? 'LEO' : 'GEO',
        inclination: satData.inclination_deg || 0,
        altitude: satData.altitude_km || position.altitude,
        snr: 0,
        status: 'tracking',
        protocols: ['CCSDS'],
        coords: {
          lat: position.latitude,
          lng: position.longitude,
          alt: position.altitude,
          velocity: 7.5
        },
        tle: {
          line1: satData.tle_line1,
          line2: satData.tle_line2,
          epoch: satData.epoch || satData.created_at || new Date().toISOString()
        },
        subsystems: []
      };
    } catch (error) {
      console.error(`Error converting satellite ${satData.name} (NORAD: ${satData.norad_id}):`, error);
      return null;
    }
  }
}

export const satelliteService = new SatelliteService();
export type { SatelliteData, TLEData };
