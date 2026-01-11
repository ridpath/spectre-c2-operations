const BACKEND_URL = 'http://localhost:8000/api/v1';

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  full_name?: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  full_name: string | null;
  role: 'admin' | 'operator' | 'analyst' | 'viewer';
  is_active: boolean;
  created_at: string;
  last_login: string | null;
}

export interface AuthResponse {
  user: UserProfile;
  tokens: AuthTokens;
}

class AuthService {
  private readonly TOKEN_KEY = 'spectre_access_token';
  private readonly REFRESH_TOKEN_KEY = 'spectre_refresh_token';
  private readonly USER_KEY = 'spectre_user';

  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    const response = await fetch(`${BACKEND_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Login failed');
    }

    const data = await response.json();
    
    this.setTokens(data.access_token, data.refresh_token);
    this.setUser(data.user);

    return {
      user: data.user,
      tokens: {
        access_token: data.access_token,
        refresh_token: data.refresh_token,
        token_type: 'Bearer'
      }
    };
  }

  async register(data: RegisterData): Promise<AuthResponse> {
    const response = await fetch(`${BACKEND_URL}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Registration failed');
    }

    const userData = await response.json();
    
    const loginResponse = await this.login({
      username: data.username,
      password: data.password
    });

    return loginResponse;
  }

  async refreshAccessToken(): Promise<string> {
    const refreshToken = this.getRefreshToken();
    
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch(`${BACKEND_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.ok) {
      this.clearAuth();
      throw new Error('Token refresh failed');
    }

    const data = await response.json();
    this.setTokens(data.access_token, refreshToken);

    return data.access_token;
  }

  async getCurrentUser(): Promise<UserProfile | null> {
    const token = this.getAccessToken();
    
    if (!token) {
      return null;
    }

    try {
      const response = await fetch(`${BACKEND_URL}/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          try {
            const newToken = await this.refreshAccessToken();
            const retryResponse = await fetch(`${BACKEND_URL}/auth/me`, {
              headers: {
                'Authorization': `Bearer ${newToken}`,
              },
            });
            
            if (retryResponse.ok) {
              const user = await retryResponse.json();
              this.setUser(user);
              return user;
            }
          } catch (e) {
            this.clearAuth();
            return null;
          }
        }
        return null;
      }

      const user = await response.json();
      this.setUser(user);
      return user;
    } catch (error) {
      console.error('Failed to get current user:', error);
      return null;
    }
  }

  logout(): void {
    this.clearAuth();
  }

  getAccessToken(): string | null {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  getRefreshToken(): string | null {
    return localStorage.getItem(this.REFRESH_TOKEN_KEY);
  }

  getStoredUser(): UserProfile | null {
    const userJson = localStorage.getItem(this.USER_KEY);
    if (!userJson) return null;
    
    try {
      return JSON.parse(userJson);
    } catch {
      return null;
    }
  }

  isAuthenticated(): boolean {
    return this.getAccessToken() !== null;
  }

  async makeAuthenticatedRequest(
    url: string,
    options: RequestInit = {}
  ): Promise<Response> {
    const token = this.getAccessToken();
    
    const headers = new Headers(options.headers);
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    let response = await fetch(url, {
      ...options,
      headers,
    });

    if (response.status === 401) {
      try {
        const newToken = await this.refreshAccessToken();
        headers.set('Authorization', `Bearer ${newToken}`);
        
        response = await fetch(url, {
          ...options,
          headers,
        });
      } catch (error) {
        this.clearAuth();
        throw new Error('Authentication failed');
      }
    }

    return response;
  }

  private setTokens(accessToken: string, refreshToken: string): void {
    localStorage.setItem(this.TOKEN_KEY, accessToken);
    localStorage.setItem(this.REFRESH_TOKEN_KEY, refreshToken);
  }

  private setUser(user: UserProfile): void {
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
  }

  private clearAuth(): void {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.REFRESH_TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
  }
}

export const authService = new AuthService();
