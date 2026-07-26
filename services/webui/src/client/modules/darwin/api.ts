// Darwin module API client - stub for batch 2
// Routes through Express proxy to darwin backend (DARWIN_BACKEND_URL)

import axios from 'axios';
import type { Review, Issue, PaginatedResponse, DashboardStats, FindingsResponse, DashboardFilters, ReviewMetrics, User } from './types';

const DARWIN_API_URL = process.env.VITE_DARWIN_API_URL || '/api/darwin';

const darwinApiClient = axios.create({
  baseURL: DARWIN_API_URL,
});

export const reviewsApi = {
  list: async (page = 1, perPage = 20, filters?: any): Promise<PaginatedResponse<Review>> => {
    const params: any = { page, per_page: perPage };
    if (filters?.status) params.status = filters.status;
    if (filters?.repo) params.repository = filters.repo;
    const response = await darwinApiClient.get('/reviews', { params });
    return response.data;
  },

  get: async (id: number): Promise<Review> => {
    const response = await darwinApiClient.get(`/reviews/${id}`);
    return response.data;
  },

  create: async (data: any) => {
    const response = await darwinApiClient.post('/reviews', data);
    return response.data;
  },

  delete: async (id: number) => {
    await darwinApiClient.delete(`/reviews/${id}`);
  },
};

export const issuesApi = {
  list: async (page = 1, perPage = 20, filters?: any): Promise<PaginatedResponse<Issue>> => {
    const params: any = { page, per_page: perPage };
    if (filters?.severity) params.severity = filters.severity;
    if (filters?.status) params.status = filters.status;
    const response = await darwinApiClient.get('/issues', { params });
    return response.data;
  },

  get: async (id: number): Promise<Issue> => {
    const response = await darwinApiClient.get(`/issues/${id}`);
    return response.data;
  },

  create: async (data: any) => {
    const response = await darwinApiClient.post('/issues', data);
    return response.data;
  },

  delete: async (id: number) => {
    await darwinApiClient.delete(`/issues/${id}`);
  },
};

export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    const response = await darwinApiClient.get('/dashboard/stats');
    return response.data;
  },

  getFindings: async (filters?: DashboardFilters & { page?: number; per_page?: number }): Promise<FindingsResponse> => {
    const response = await darwinApiClient.get('/dashboard/findings', { params: filters });
    return response.data;
  },
};

export const analyticsApi = {
  metrics: async (): Promise<ReviewMetrics> => {
    const response = await darwinApiClient.get('/analytics/metrics');
    return response.data;
  },

  activityHistory: async (days = 30): Promise<Array<{ date: string; count: number }>> => {
    const response = await darwinApiClient.get('/analytics/activity', { params: { days } });
    return response.data;
  },
};

// Stub APIs for other darwin resources
export const tenantsApi = {
  list: async (page = 1, perPage = 20) => {
    const response = await darwinApiClient.get('/tenants', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number) => {
    const response = await darwinApiClient.get(`/tenants/${id}`);
    return response.data;
  },

  create: async (data: any) => {
    const response = await darwinApiClient.post('/tenants', data);
    return response.data;
  },

  delete: async (id: number) => {
    await darwinApiClient.delete(`/tenants/${id}`);
  },
};

export const rolesApi = {
  list: async (page = 1, perPage = 20) => {
    const response = await darwinApiClient.get('/roles', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number) => {
    const response = await darwinApiClient.get(`/roles/${id}`);
    return response.data;
  },

  create: async (data: any) => {
    const response = await darwinApiClient.post('/roles', data);
    return response.data;
  },

  delete: async (id: number) => {
    await darwinApiClient.delete(`/roles/${id}`);
  },
};

export const teamsApi = {
  list: async (page = 1, perPage = 20) => {
    const response = await darwinApiClient.get('/teams', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number) => {
    const response = await darwinApiClient.get(`/teams/${id}`);
    return response.data;
  },

  create: async (data: any) => {
    const response = await darwinApiClient.post('/teams', data);
    return response.data;
  },

  getMembers: async (id: number) => {
    const response = await darwinApiClient.get(`/teams/${id}/members`);
    return response.data;
  },

  removeMember: async (teamId: number, userId: number) => {
    await darwinApiClient.delete(`/teams/${teamId}/members/${userId}`);
  },
};

export const usersApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<User>> => {
    const response = await darwinApiClient.get('/users', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number) => {
    const response = await darwinApiClient.get(`/users/${id}`);
    return response.data;
  },

  create: async (data: any) => {
    const response = await darwinApiClient.post('/users', data);
    return response.data;
  },

  delete: async (id: number) => {
    await darwinApiClient.delete(`/users/${id}`);
  },
};

export const repositoriesApi = {
  list: async (page = 1, perPage = 20) => {
    const response = await darwinApiClient.get('/repositories', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number) => {
    const response = await darwinApiClient.get(`/repositories/${id}`);
    return response.data;
  },

  create: async (data: any) => {
    const response = await darwinApiClient.post('/repositories', data);
    return response.data;
  },

  delete: async (id: number) => {
    await darwinApiClient.delete(`/repositories/${id}`);
  },
};

export const configApi = {
  get: async () => {
    const response = await darwinApiClient.get('/config');
    return response.data;
  },

  update: async (config: any) => {
    const response = await darwinApiClient.put('/config', config);
    return response.data;
  },
};

export const elderApi = {
  push: async (filters?: any) => {
    const response = await darwinApiClient.post('/integrations/elder', filters || {});
    return response.data;
  },

  test: async () => {
    const response = await darwinApiClient.post('/integrations/elder/test');
    return response.data;
  },

  getStats: async () => {
    const response = await darwinApiClient.get('/integrations/elder/stats');
    return response.data;
  },
};

export default darwinApiClient;
