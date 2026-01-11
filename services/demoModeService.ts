class DemoModeService {
  private isDemoMode: boolean = false;
  private listeners: Set<(isDemo: boolean) => void> = new Set();

  setDemoMode(enabled: boolean): void {
    this.isDemoMode = enabled;
    localStorage.setItem('spectre_demo_mode', enabled ? 'true' : 'false');
    this.notifyListeners();
  }

  getDemoMode(): boolean {
    return this.isDemoMode;
  }

  initialize(): void {
    const stored = localStorage.getItem('spectre_demo_mode');
    this.isDemoMode = stored === 'true';
  }

  subscribe(callback: (isDemo: boolean) => void): () => void {
    this.listeners.add(callback);
    callback(this.isDemoMode);
    return () => {
      this.listeners.delete(callback);
    };
  }

  private notifyListeners(): void {
    this.listeners.forEach(listener => listener(this.isDemoMode));
  }
}

export const demoModeService = new DemoModeService();
demoModeService.initialize();
