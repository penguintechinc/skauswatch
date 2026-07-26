// Darwin module types - stub for batch 2
// These will be properly typed when darwin backend is integrated

export interface DashboardStats {
  overview: {
    total_repositories: number;
    total_reviews: number;
    pending_reviews: number;
  };
  findings: Record<string, number>;
  platforms: Record<string, number>;
}

export interface Finding {
  id: string;
  repository: { name: string; display_name: string; platform: string };
  file_path: string;
  severity: FindingSeverity;
  title: string;
  body?: string;
  line_start: number;
  line_end: number;
  category: string;
}

export interface FindingsResponse {
  findings: Finding[];
  pagination: { total: number; pages: number };
}

export type Platform = string;
export type FindingSeverity = 'critical' | 'major' | 'minor' | 'suggestion';

export interface DashboardFilters {
  platform?: Platform;
  organization?: string;
  severity?: FindingSeverity;
  repository_id?: string;
}

export interface Review {
  id: number;
  pull_request_id: number;
  pull_request?: any;
  status: string;
  comments?: ReviewComment[];
  reviewer?: string;
  [key: string]: any;
}

export interface ReviewComment {
  id: number;
  content: string;
  line?: number;
  file?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: { page: number; per_page: number; total: number; pages: number };
}

export interface ReviewMetrics {
  total_reviews: number;
  average_review_time: number;
  recent_activity?: number;
  changes_requested?: number;
  approved?: number;
  total_issues?: number;
  [key: string]: any;
}

export interface User {
  id?: number;
  name?: string;
  email?: string;
  role?: 'viewer' | 'admin' | 'maintainer';
  [key: string]: any;
}

export interface CreateUserData {
  [key: string]: any;
}

export interface UpdateUserData {
  [key: string]: any;
}

export interface Repository {
  id?: number;
  name?: string;
  url?: string;
  [key: string]: any;
}

export interface CreateRepositoryData {
  [key: string]: any;
}

export interface UpdateRepositoryData {
  [key: string]: any;
}

export interface RepositoryListResponse {
  repositories?: Repository[];
  [key: string]: any;
}

export interface OrganizationsResponse {
  organizations?: any[];
  [key: string]: any;
}

export interface Issue {
  id?: number;
  title?: string;
  status?: string;
  [key: string]: any;
}

export interface PullRequest {
  id?: number;
  title?: string;
  [key: string]: any;
}

export interface RepositoryConfig {
  id?: number;
  name?: string;
  [key: string]: any;
}
