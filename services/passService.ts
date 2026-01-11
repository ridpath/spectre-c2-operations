import { PassPrediction, AOSWindow, GroundStation } from '../types';
import { authService } from './authService';

const BACKEND_URL = 'http://localhost:8000/api/v1';

export const passService = {
  async predictPasses(
    noradId: number,
    groundStation: GroundStation,
    hoursAhead: number = 24
  ): Promise<PassPrediction> {
    try {
      const params = new URLSearchParams({
        norad_id: noradId.toString(),
        latitude: groundStation.latitude.toString(),
        longitude: groundStation.longitude.toString(),
        altitude: groundStation.altitude.toString(),
        min_elevation: groundStation.minElevation.toString(),
        hours_ahead: hoursAhead.toString()
      });

      const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/passes/predict?${params}`);

      if (!response.ok) {
        throw new Error('Failed to predict passes');
      }

      const data = await response.json();
      return {
        satellite: data.satellite,
        noradId: data.norad_id,
        passes: data.passes.map((p: any) => ({
          id: p.id,
          startTime: new Date(p.start_time),
          endTime: new Date(p.end_time),
          maxElevation: p.max_elevation,
          isCurrent: p.is_current
        })),
        groundStation: {
          name: groundStation.name,
          latitude: data.ground_station.latitude,
          longitude: data.ground_station.longitude,
          altitude: data.ground_station.altitude,
          minElevation: data.ground_station.min_elevation
        },
        calculatedAt: new Date(data.calculated_at)
      };
    } catch (error) {
      console.error('Pass prediction error:', error);
      return {
        satellite: `NORAD ${noradId}`,
        noradId,
        passes: [],
        groundStation,
        calculatedAt: new Date()
      };
    }
  }
};
