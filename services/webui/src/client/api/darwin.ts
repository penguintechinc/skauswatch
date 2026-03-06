import api from '../lib/api';
import type {
  DarwinRepo,
  DarwinRepoCreateRequest,
  DarwinRepoUpdateRequest,
  DarwinReview,
  DarwinReviewCreateRequest,
  DarwinPlan,
  DarwinPlanCreateRequest,
  DarwinStatus,
} from '../types/darwin';

const BASE = '/darwin';

export const darwinApi = {
  // ── Status ─────────────────────────────────────────────────────────
  async getStatus(): Promise<DarwinStatus> {
    const res = await api.get<DarwinStatus>(`${BASE}/status`);
    return res.data;
  },

  // ── Repositories ───────────────────────────────────────────────────
  async listRepos(): Promise<DarwinRepo[]> {
    const res = await api.get<DarwinRepo[]>(`${BASE}/repos`);
    return res.data;
  },

  async getRepo(id: number): Promise<DarwinRepo> {
    const res = await api.get<DarwinRepo>(`${BASE}/repos/${id}`);
    return res.data;
  },

  async createRepo(data: DarwinRepoCreateRequest): Promise<DarwinRepo> {
    const res = await api.post<DarwinRepo>(`${BASE}/repos`, data);
    return res.data;
  },

  async updateRepo(id: number, data: DarwinRepoUpdateRequest): Promise<DarwinRepo> {
    const res = await api.put<DarwinRepo>(`${BASE}/repos/${id}`, data);
    return res.data;
  },

  async deleteRepo(id: number): Promise<void> {
    await api.delete(`${BASE}/repos/${id}`);
  },

  // ── Reviews ────────────────────────────────────────────────────────
  async listReviews(params?: { repo_config_id?: number; status?: string }): Promise<DarwinReview[]> {
    const res = await api.get<DarwinReview[]>(`${BASE}/reviews`, { params });
    return res.data;
  },

  async getReview(id: number): Promise<DarwinReview> {
    const res = await api.get<DarwinReview>(`${BASE}/reviews/${id}`);
    return res.data;
  },

  async createReview(data: DarwinReviewCreateRequest): Promise<DarwinReview> {
    const res = await api.post<DarwinReview>(`${BASE}/reviews`, data);
    return res.data;
  },

  // ── Issue Plans ────────────────────────────────────────────────────
  async listPlans(params?: { repo_config_id?: number; status?: string }): Promise<DarwinPlan[]> {
    const res = await api.get<DarwinPlan[]>(`${BASE}/plans`, { params });
    return res.data;
  },

  async getPlan(id: number): Promise<DarwinPlan> {
    const res = await api.get<DarwinPlan>(`${BASE}/plans/${id}`);
    return res.data;
  },

  async createPlan(data: DarwinPlanCreateRequest): Promise<DarwinPlan> {
    const res = await api.post<DarwinPlan>(`${BASE}/plans`, data);
    return res.data;
  },
};
