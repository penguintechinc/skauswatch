import api from '../lib/api';
import type {
  PullRequest,
  Review,
  ReviewComment,
  Issue,
  RepositoryConfig,
  ReviewMetrics,
  PaginatedResponse,
} from '../types';

// Reviews API
export const reviewsApi = {
  list: async (
    page = 1,
    perPage = 20,
    filters?: { status?: string; repo?: string; dateFrom?: string; dateTo?: string }
  ): Promise<PaginatedResponse<Review>> => {
    const params: any = { page, per_page: perPage };
    if (filters?.status) params.status = filters.status;
    if (filters?.repo) params.repository = filters.repo;
    if (filters?.dateFrom) params.date_from = filters.dateFrom;
    if (filters?.dateTo) params.date_to = filters.dateTo;

    const response = await api.get('/reviews', { params });
    return response.data;
  },

  get: async (id: number): Promise<Review> => {
    const response = await api.get(`/reviews/${id}`);
    return response.data;
  },

  create: async (data: {
    pull_request_id: number;
    status: string;
  }): Promise<Review> => {
    const response = await api.post('/reviews', data);
    return response.data;
  },

  update: async (
    id: number,
    data: { status?: string; comments?: string }
  ): Promise<Review> => {
    const response = await api.put(`/reviews/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/reviews/${id}`);
  },

  addComment: async (
    reviewId: number,
    data: { content: string; line?: number; file?: string }
  ): Promise<ReviewComment> => {
    const response = await api.post(`/reviews/${reviewId}/comments`, data);
    return response.data;
  },
};

// Pull Requests API
export const pullRequestsApi = {
  list: async (
    page = 1,
    perPage = 20,
    filters?: { status?: string; repo?: string; author?: string }
  ): Promise<PaginatedResponse<PullRequest>> => {
    const params: any = { page, per_page: perPage };
    if (filters?.status) params.status = filters.status;
    if (filters?.repo) params.repository = filters.repo;
    if (filters?.author) params.author = filters.author;

    const response = await api.get('/pull-requests', { params });
    return response.data;
  },

  get: async (id: number): Promise<PullRequest> => {
    const response = await api.get(`/pull-requests/${id}`);
    return response.data;
  },
};

// Issues API
export const issuesApi = {
  list: async (
    page = 1,
    perPage = 20,
    filters?: { severity?: string; status?: string; repo?: string }
  ): Promise<PaginatedResponse<Issue>> => {
    const params: any = { page, per_page: perPage };
    if (filters?.severity) params.severity = filters.severity;
    if (filters?.status) params.status = filters.status;
    if (filters?.repo) params.repository = filters.repo;

    const response = await api.get('/issues', { params });
    return response.data;
  },

  get: async (id: number): Promise<Issue> => {
    const response = await api.get(`/issues/${id}`);
    return response.data;
  },

  create: async (data: {
    title: string;
    description: string;
    repository: string;
    severity: string;
  }): Promise<Issue> => {
    const response = await api.post('/issues', data);
    return response.data;
  },

  update: async (
    id: number,
    data: { status?: string; assigned_to?: string }
  ): Promise<Issue> => {
    const response = await api.put(`/issues/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/issues/${id}`);
  },
};

// Repository Configuration API
export const repositoriesApi = {
  list: async (page = 1, perPage = 20): Promise<PaginatedResponse<RepositoryConfig>> => {
    const response = await api.get('/repositories', { params: { page, per_page: perPage } });
    return response.data;
  },

  get: async (id: number): Promise<RepositoryConfig> => {
    const response = await api.get(`/repositories/${id}`);
    return response.data;
  },

  create: async (data: {
    name: string;
    url: string;
    access_token: string;
  }): Promise<RepositoryConfig> => {
    const response = await api.post('/repositories', data);
    return response.data;
  },

  update: async (
    id: number,
    data: { url?: string; access_token?: string; is_active?: boolean }
  ): Promise<RepositoryConfig> => {
    const response = await api.put(`/repositories/${id}`, data);
    return response.data;
  },

  delete: async (id: number): Promise<void> => {
    await api.delete(`/repositories/${id}`);
  },

  testConnection: async (id: number): Promise<{ success: boolean; message: string }> => {
    const response = await api.post(`/repositories/${id}/test`, {});
    return response.data;
  },
};

// Analytics API
export const analyticsApi = {
  metrics: async (): Promise<ReviewMetrics> => {
    const response = await api.get('/analytics/metrics');
    return response.data;
  },

  activityHistory: async (
    days = 30
  ): Promise<Array<{ date: string; count: number }>> => {
    const response = await api.get('/analytics/activity', { params: { days } });
    return response.data;
  },
};
