// CodeScan module API client - routes through Express proxy to codescan backend

import axios from 'axios';
import type {
  Review,
  ReviewComment,
  Issue,
  PaginatedResponse,
  DashboardStats,
  FindingsResponse,
  DashboardFilters,
  ReviewMetrics,
  User,
  RepositoryConfig,
  CreateRepositoryData,
  UpdateRepositoryData,
  RepositoryListResponse,
  OrganizationsResponse,
  CreateUserData,
  UpdateUserData,
} from './types';

const CODESCAN_API_URL = process.env.VITE_CODESCAN_API_URL || '/api/codescan';

const codescanApiClient = axios.create({
  baseURL: CODESCAN_API_URL,
});

export const reviewsApi = {
  list: async (page = 1, perPage = 20, filters?: Record<string, any>): Promise<PaginatedResponse<Review>> => {
    const params: Record<string, any> = { page, per_page: perPage };
    if (filters?.status) params.status = filters.status;
    if (filters?.repo) params.repository = filters.repo;
    const response = await codescanApiClient.get('/reviews', { params });
    return response.data;
  },

  get: async (id: number): Promise<Review> => {
    const response = await codescanApiClient.get(`/reviews/${id}`);
    return response.data;
  },

  create: async (data: Partial<Review>): Promise<Review> => {
    const response = await codescanApiClient.post('/reviews', data);
    return response.data;
  },

  addComment: async (reviewId: number, data: Partial<ReviewComment>): Promise<ReviewComment> => {
    const response = await codescanApiClient.post(`/reviews/${reviewId}/comments`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await codescanApiClient.delete(`/reviews/${id}`);
  },
};

export const issuesApi = {
  list: async (page = 1, perPage = 20, filters?: Record<string, any>): Promise<PaginatedResponse<Issue>> => {
    const params: Record<string, any> = { page, per_page: perPage };
    if (filters?.severity) params.severity = filters.severity;
    if (filters?.status) params.status = filters.status;
    const response = await codescanApiClient.get('/issues', { params });
    return response.data;
  },

  get: async (id: number): Promise<Issue> => {
    const response = await codescanApiClient.get(`/issues/${id}`);
    return response.data;
  },

  create: async (data: Partial<Issue>): Promise<Issue> => {
    const response = await codescanApiClient.post('/issues', data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await codescanApiClient.delete(`/issues/${id}`);
  },
};

export const dashboardApi = {
  getStats: async (): Promise<DashboardStats> => {
    const response = await codescanApiClient.get('/dashboard/stats');
    return response.data;
  },

  getFindings: async (
    filters?: DashboardFilters & { page?: number; per_page?: number }
  ): Promise<FindingsResponse> => {
    const response = await codescanApiClient.get('/dashboard/findings', { params: filters });
    return response.data;
  },
};

export const analyticsApi = {
  metrics: async (): Promise<ReviewMetrics> => {
    const response = await codescanApiClient.get('/analytics/metrics');
    return response.data;
  },

  activityHistory: async (days = 30): Promise<Array<{ date: string; count: number }>> => {
    const response = await codescanApiClient.get('/analytics/activity', { params: { days } });
    return response.data;
  },
};

export const tenantsApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<Record<string, any>>> => {
    const response = await codescanApiClient.get('/tenants', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<Record<string, any>> => {
    const response = await codescanApiClient.get(`/tenants/${id}`);
    return response.data;
  },

  create: async (data: Record<string, any>): Promise<Record<string, any>> => {
    const response = await codescanApiClient.post('/tenants', data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await codescanApiClient.delete(`/tenants/${id}`);
  },

  getMembers: async (id: number): Promise<User[]> => {
    const response = await codescanApiClient.get(`/tenants/${id}/members`);
    return response.data;
  },

  addMember: async (tenantId: number, memberData: number | Record<string, any>): Promise<void> => {
    const data = typeof memberData === 'number' ? { user_id: memberData } : memberData;
    await codescanApiClient.post(`/tenants/${tenantId}/members`, data);
  },

  removeMember: async (tenantId: number, userId: number): Promise<void> => {
    await codescanApiClient.delete(`/tenants/${tenantId}/members/${userId}`);
  },
};

export const rolesApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<Record<string, any>>> => {
    const response = await codescanApiClient.get('/roles', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<Record<string, any>> => {
    const response = await codescanApiClient.get(`/roles/${id}`);
    return response.data;
  },

  create: async (data: Record<string, any>): Promise<Record<string, any>> => {
    const response = await codescanApiClient.post('/roles', data);
    return response.data;
  },

  update: async (id: number, data: Record<string, any>): Promise<Record<string, any>> => {
    const response = await codescanApiClient.put(`/roles/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await codescanApiClient.delete(`/roles/${id}`);
  },

  listRoles: async (page = 1, perPage = 20): Promise<PaginatedResponse<Record<string, any>>> => {
    const response = await codescanApiClient.get('/roles', { params: { page, per_page: perPage } });
    return response.data;
  },

  listScopes: async (): Promise<Record<string, any>[]> => {
    const response = await codescanApiClient.get('/scopes');
    return response.data;
  },
};

export const teamsApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<Record<string, any>>> => {
    const response = await codescanApiClient.get('/teams', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<Record<string, any>> => {
    const response = await codescanApiClient.get(`/teams/${id}`);
    return response.data;
  },

  create: async (data: Record<string, any>): Promise<Record<string, any>> => {
    const response = await codescanApiClient.post('/teams', data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await codescanApiClient.delete(`/teams/${id}`);
  },

  getMembers: async (id: number): Promise<User[]> => {
    const response = await codescanApiClient.get(`/teams/${id}/members`);
    return response.data;
  },

  addMember: async (teamId: number, memberData: number | Record<string, any>): Promise<void> => {
    const data = typeof memberData === 'number' ? { user_id: memberData } : memberData;
    await codescanApiClient.post(`/teams/${teamId}/members`, data);
  },

  removeMember: async (teamId: number, userId: number): Promise<void> => {
    await codescanApiClient.delete(`/teams/${teamId}/members/${userId}`);
  },
};

export const usersApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<User>> => {
    const response = await codescanApiClient.get('/users', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<User> => {
    const response = await codescanApiClient.get(`/users/${id}`);
    return response.data;
  },

  create: async (data: CreateUserData): Promise<User> => {
    const response = await codescanApiClient.post('/users', data);
    return response.data;
  },

  update: async (id: number, data: UpdateUserData): Promise<User> => {
    const response = await codescanApiClient.put(`/users/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await codescanApiClient.delete(`/users/${id}`);
  },
};

export const repositoriesApi = {
  list: async (page = 1, perPage = 20): Promise<RepositoryListResponse> => {
    const response = await codescanApiClient.get('/repositories', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<RepositoryConfig> => {
    const response = await codescanApiClient.get(`/repositories/${id}`);
    return response.data;
  },

  create: async (data: CreateRepositoryData): Promise<RepositoryConfig> => {
    const response = await codescanApiClient.post('/repositories', data);
    return response.data;
  },

  update: async (id: number, data: UpdateRepositoryData): Promise<RepositoryConfig> => {
    const response = await codescanApiClient.put(`/repositories/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await codescanApiClient.delete(`/repositories/${id}`);
  },

  listOrganizations: async (): Promise<OrganizationsResponse> => {
    const response = await codescanApiClient.get('/repositories/organizations');
    return response.data;
  },

  testConnection: async (id: number): Promise<{ success: boolean; message: string }> => {
    const response = await codescanApiClient.post(`/repositories/${id}/test`, {});
    return response.data;
  },
};

export const configApi = {
  get: async (): Promise<Record<string, any>> => {
    const response = await codescanApiClient.get('/config');
    return response.data;
  },

  update: async (config: Record<string, any>): Promise<void> => {
    await codescanApiClient.put('/config', config);
  },
};

export const elderApi = {
  push: async (filters?: Record<string, any>): Promise<Record<string, any>> => {
    const response = await codescanApiClient.post('/integrations/elder', filters || {});
    return response.data;
  },

  test: async (): Promise<Record<string, any>> => {
    const response = await codescanApiClient.post('/integrations/elder/test');
    return response.data;
  },

  getStats: async (): Promise<Record<string, any>> => {
    const response = await codescanApiClient.get('/integrations/elder/stats');
    return response.data;
  },
};

export default codescanApiClient;
