import api from '../lib/api';
import type {
  CodeScanRepo,
  CodeScanRepoCreateRequest,
  CodeScanRepoUpdateRequest,
  CodeScanReview,
  CodeScanReviewCreateRequest,
  CodeScanPlan,
  CodeScanPlanCreateRequest,
  CodeScanStatus,
} from '../types/codescan';

const BASE = '/codescan';

export const codescanApi = {
  // ── Status ─────────────────────────────────────────────────────────
  async getStatus(): Promise<CodeScanStatus> {
    const res = await api.get<CodeScanStatus>(`${BASE}/status`);
    return res.data;
  },

  // ── Repositories ───────────────────────────────────────────────────
  async listRepos(): Promise<CodeScanRepo[]> {
    const res = await api.get<CodeScanRepo[]>(`${BASE}/repos`);
    return res.data;
  },

  async getRepo(id: number): Promise<CodeScanRepo> {
    const res = await api.get<CodeScanRepo>(`${BASE}/repos/${id}`);
    return res.data;
  },

  async createRepo(data: CodeScanRepoCreateRequest): Promise<CodeScanRepo> {
    const res = await api.post<CodeScanRepo>(`${BASE}/repos`, data);
    return res.data;
  },

  async updateRepo(id: number, data: CodeScanRepoUpdateRequest): Promise<CodeScanRepo> {
    const res = await api.put<CodeScanRepo>(`${BASE}/repos/${id}`, data);
    return res.data;
  },

  async deleteRepo(id: number): Promise<void> {
    await api.delete(`${BASE}/repos/${id}`);
  },

  // ── Reviews ────────────────────────────────────────────────────────
  async listReviews(params?: { repo_config_id?: number; status?: string }): Promise<CodeScanReview[]> {
    const res = await api.get<CodeScanReview[]>(`${BASE}/reviews`, { params });
    return res.data;
  },

  async getReview(id: number): Promise<CodeScanReview> {
    const res = await api.get<CodeScanReview>(`${BASE}/reviews/${id}`);
    return res.data;
  },

  async createReview(data: CodeScanReviewCreateRequest): Promise<CodeScanReview> {
    const res = await api.post<CodeScanReview>(`${BASE}/reviews`, data);
    return res.data;
  },

  // ── Issue Plans ────────────────────────────────────────────────────
  async listPlans(params?: { repo_config_id?: number; status?: string }): Promise<CodeScanPlan[]> {
    const res = await api.get<CodeScanPlan[]>(`${BASE}/plans`, { params });
    return res.data;
  },

  async getPlan(id: number): Promise<CodeScanPlan> {
    const res = await api.get<CodeScanPlan>(`${BASE}/plans/${id}`);
    return res.data;
  },

  async createPlan(data: CodeScanPlanCreateRequest): Promise<CodeScanPlan> {
    const res = await api.post<CodeScanPlan>(`${BASE}/plans`, data);
    return res.data;
  },
};
