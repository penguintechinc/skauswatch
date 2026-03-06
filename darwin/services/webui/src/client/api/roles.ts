import api from '../lib/api';
import type { PaginatedResponse } from '../types';

export interface Scope {
  id: number;
  name: string;
  slug: string;
  description?: string;
  category: string;
}

export interface Role {
  id: number;
  name: string;
  slug: string;
  description?: string;
  level: 'global' | 'tenant' | 'team' | 'resource';
  scope_count: number;
  is_active: boolean;
  scopes?: Scope[];
  created_at: string;
  updated_at: string;
}

export interface CreateRoleData {
  name: string;
  slug: string;
  description?: string;
  level: 'global' | 'tenant' | 'team' | 'resource';
  scope_ids: number[];
}

export interface UpdateRoleData {
  name?: string;
  slug?: string;
  description?: string;
  level?: 'global' | 'tenant' | 'team' | 'resource';
  scope_ids?: number[];
  is_active?: boolean;
}

export const rolesApi = {
  listScopes: async (): Promise<Scope[]> => {
    const response = await api.get('/roles/scopes');
    return (response.data as any).items || response.data || [];
  },

  listRoles: async (level?: string, page = 1, perPage = 20): Promise<PaginatedResponse<Role>> => {
    const params: any = { page, per_page: perPage };
    if (level) {
      params.level = level;
    }
    const response = await api.get('/roles', { params });
    return response.data;
  },

  get: async (id: number): Promise<Role> => {
    const response = await api.get(`/roles/${id}`);
    return response.data;
  },

  create: async (data: CreateRoleData): Promise<Role> => {
    const response = await api.post('/roles', data);
    return response.data;
  },

  update: async (id: number, data: UpdateRoleData): Promise<Role> => {
    const response = await api.put(`/roles/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/roles/${id}`);
  },
};
