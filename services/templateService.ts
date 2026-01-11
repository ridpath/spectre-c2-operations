import { CommandTemplate } from '../types';
import { authService } from './authService';

const BACKEND_URL = 'http://localhost:8000/api/v1';

export const templateService = {
  async getTemplates(category?: string): Promise<CommandTemplate[]> {
    try {
      const url = category
        ? `${BACKEND_URL}/templates?category=${category}`
        : `${BACKEND_URL}/templates`;

      const response = await authService.makeAuthenticatedRequest(url);

      if (!response.ok) {
        throw new Error('Failed to fetch templates');
      }

      const data = await response.json();
      return data.templates;
    } catch (error) {
      console.error('Failed to fetch templates:', error);
      return [];
    }
  },

  async createTemplate(template: Omit<CommandTemplate, 'id'>): Promise<CommandTemplate> {
    const response = await authService.makeAuthenticatedRequest(`${BACKEND_URL}/templates`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(template)
    });

    if (!response.ok) {
      throw new Error('Failed to create template');
    }

    return await response.json();
  }
};
