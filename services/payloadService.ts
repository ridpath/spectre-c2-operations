import { authService } from './authService';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

interface PayloadTemplate {
  id: string;
  name: string;
  description: string;
  format: string;
  evasion_level: string;
}

interface PayloadGenerateRequest {
  template_id: string;
  lhost: string;
  lport: number;
  arch?: string;
  format?: string;
  encode?: boolean;
  iterations?: number;
  obfuscation?: string;
  mission_id?: string;
}

interface DropperGenerateRequest {
  payload_type: string;
  lhost: string;
  lport: number;
  evasion_features?: string[];
  delivery_method?: string;
}

async function getTemplates(): Promise<{ templates: PayloadTemplate[], formats: string[], total: number }> {
  try {
    const token = authService.getToken();
    const response = await fetch(`${API_URL}/payloads/templates`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });
    
    if (response.status === 401 || response.status === 403) {
      return { templates: [], formats: [], total: 0 };
    }
    
    if (!response.ok) {
      throw new Error(`Failed to fetch payload templates: ${response.statusText}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error fetching payload templates:', error);
    throw error;
  }
}

async function generatePayload(request: PayloadGenerateRequest): Promise<any> {
  try {
    const token = authService.getToken();
    const response = await fetch(`${API_URL}/payloads/generate`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(request)
    });
    
    if (response.status === 401 || response.status === 403) {
      throw new Error('Unauthorized');
    }
    
    if (!response.ok) {
      throw new Error(`Payload generation failed: ${response.statusText}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error generating payload:', error);
    throw error;
  }
}

async function generateDropper(request: DropperGenerateRequest): Promise<any> {
  try {
    const token = authService.getToken();
    const response = await fetch(`${API_URL}/payloads/dropper`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(request)
    });
    
    if (response.status === 401 || response.status === 403) {
      throw new Error('Unauthorized');
    }
    
    if (!response.ok) {
      throw new Error(`Dropper generation failed: ${response.statusText}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error generating dropper:', error);
    throw error;
  }
}

export const payloadService = {
  getTemplates,
  generatePayload,
  generateDropper
};
