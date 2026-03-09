import { useState, useCallback } from 'react';
import api from '../lib/api';
import type {
  User,
  CreateUserData,
  UpdateUserData,
  PaginatedResponse,
  Repository,
  CreateRepositoryData,
  UpdateRepositoryData,
  RepositoryListResponse,
  OrganizationsResponse,
  DashboardStats,
  FindingsResponse,
  DashboardFilters,
} from '../types';

// Generic API hook for loading states
export function useApiCall<T>() {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const execute = useCallback(async (apiCall: () => Promise<T>) => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await apiCall();
      setData(result);
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'An error occurred';
      setError(message);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  return { data, error, isLoading, execute, setData };
}

// Users API
export const usersApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<User>> => {
    const response = await api.get('/users', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<User> => {
    const response = await api.get(`/users/${id}`);
    return response.data;
  },

  create: async (data: CreateUserData): Promise<User> => {
    const response = await api.post('/users', data);
    return response.data;
  },

  update: async (id: number, data: UpdateUserData): Promise<User> => {
    const response = await api.put(`/users/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/users/${id}`);
  },
};

// Hello world API (example)
export const helloApi = {
  get: async (): Promise<{ message: string; timestamp: string }> => {
    const response = await api.get('/hello');
    return response.data;
  },

  getProtected: async (): Promise<{ message: string; user: string; role: string }> => {
    const response = await api.get('/hello/protected');
    return response.data;
  },
};

// Go backend API (high-performance endpoints)
export const goApi = {
  status: async (): Promise<Record<string, unknown>> => {
    const response = await api.get('/go/status');
    return response.data;
  },

  numaInfo: async (): Promise<Record<string, unknown>> => {
    const response = await api.get('/go/numa/info');
    return response.data;
  },

  memoryStats: async (): Promise<Record<string, unknown>> => {
    const response = await api.get('/go/memory/stats');
    return response.data;
  },
};

// Repositories API
export const repositoriesApi = {
  list: async (
    filters?: {
      platform?: string;
      organization?: string;
      enabled?: boolean;
      page?: number;
      per_page?: number;
    }
  ): Promise<RepositoryListResponse> => {
    const response = await api.get('/repositories', { params: filters });
    return response.data;
  },

  get: async (id: number): Promise<Repository> => {
    const response = await api.get(`/repositories/${id}`);
    return response.data;
  },

  create: async (data: CreateRepositoryData): Promise<Repository> => {
    const response = await api.post('/repositories', data);
    return response.data;
  },

  update: async (id: number, data: UpdateRepositoryData): Promise<Repository> => {
    const response = await api.put(`/repositories/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/repositories/${id}`);
  },

  listOrganizations: async (): Promise<OrganizationsResponse> => {
    const response = await api.get('/repositories/organizations');
    return response.data;
  },
};

// Dashboard API
export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    const response = await api.get('/dashboard/stats');
    return response.data;
  },

  getFindings: async (
    filters?: DashboardFilters & { page?: number; per_page?: number }
  ): Promise<FindingsResponse> => {
    const response = await api.get('/dashboard/findings', { params: filters });
    return response.data;
  },
};

// Configuration API
export const configApi = {
  get: async (): Promise<any> => {
    const response = await api.get('/config');
    return response.data;
  },

  update: async (config: any): Promise<void> => {
    await api.put('/config', config);
  },
};

// Elder Integration API
export const elderApi = {
  push: async (filters?: { repository_filter?: string; severity_filter?: string; category_filter?: string }): Promise<any> => {
    const response = await api.post('/integrations/elder', filters || {});
    return response.data;
  },

  test: async (): Promise<any> => {
    const response = await api.post('/integrations/elder/test');
    return response.data;
  },

  getStats: async (): Promise<any> => {
    const response = await api.get('/integrations/elder/stats');
    return response.data;
  },
};
