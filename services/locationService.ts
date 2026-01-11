interface Coordinates {
  latitude: number;
  longitude: number;
  altitude?: number;
  accuracy?: number;
}

interface LocationState {
  coords: Coordinates | null;
  error: string | null;
  isLoading: boolean;
}

class LocationService {
  private coords: Coordinates | null = null;
  private listeners: Set<(coords: Coordinates | null) => void> = new Set();
  private watchId: number | null = null;
  
  async requestLocation(): Promise<Coordinates> {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        const defaultCoords: Coordinates = { latitude: 0, longitude: 0 };
        this.coords = defaultCoords;
        this.notifyListeners();
        reject(new Error('Geolocation not supported by browser'));
        return;
      }

      navigator.geolocation.getCurrentPosition(
        (position) => {
          this.coords = {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            altitude: position.coords.altitude || undefined,
            accuracy: position.coords.accuracy
          };
          this.notifyListeners();
          resolve(this.coords);
        },
        (error) => {
          const defaultCoords: Coordinates = { 
            latitude: 37.7749,
            longitude: -122.4194
          };
          this.coords = defaultCoords;
          this.notifyListeners();
          console.warn('Geolocation error, using default:', error.message);
          resolve(defaultCoords);
        },
        {
          enableHighAccuracy: true,
          timeout: 5000,
          maximumAge: 0
        }
      );
    });
  }

  startWatching(): void {
    if (!navigator.geolocation || this.watchId !== null) return;

    this.watchId = navigator.geolocation.watchPosition(
      (position) => {
        this.coords = {
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
          altitude: position.coords.altitude || undefined,
          accuracy: position.coords.accuracy
        };
        this.notifyListeners();
      },
      (error) => {
        console.error('Location watch error:', error);
      },
      {
        enableHighAccuracy: false,
        maximumAge: 30000
      }
    );
  }

  stopWatching(): void {
    if (this.watchId !== null && navigator.geolocation) {
      navigator.geolocation.clearWatch(this.watchId);
      this.watchId = null;
    }
  }

  setManualLocation(lat: number, lng: number, alt?: number): void {
    this.coords = {
      latitude: lat,
      longitude: lng,
      altitude: alt
    };
    this.notifyListeners();
  }

  getCurrentLocation(): Coordinates | null {
    return this.coords;
  }

  subscribe(callback: (coords: Coordinates | null) => void): () => void {
    this.listeners.add(callback);
    if (this.coords) {
      callback(this.coords);
    }
    return () => {
      this.listeners.delete(callback);
    };
  }

  private notifyListeners(): void {
    this.listeners.forEach(listener => listener(this.coords));
  }

  async ensureLocation(): Promise<Coordinates> {
    if (this.coords) {
      return this.coords;
    }
    return this.requestLocation();
  }
}

export const locationService = new LocationService();
export type { Coordinates, LocationState };
