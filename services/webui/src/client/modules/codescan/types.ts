// CodeScan module types - ported from original codescan webui

// User types
export type UserRole = 'admin' | 'maintainer' | 'viewer';

export interface User {
  id: number;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  updated_at: string | null;
}

export interface CreateUserData {
  email: string;
  password: string;
  full_name: string;
  role: UserRole;
  tenant_id?: number;
  team_id?: number;
  [key: string]: any;
}

export interface UpdateUserData {
  email?: string;
  full_name?: string;
  role?: UserRole;
  is_active?: boolean;
  password?: string;
  [key: string]: any;
}

// Auth types
export interface LoginCredentials {
  email: string;
  password: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface AuthState {
  user: User | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

// API Response types
export interface ApiResponse<T> {
  data?: T;
  error?: string;
  message?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

// Navigation types
export interface NavItem {
  label: string;
  path: string;
  icon?: string;
  roles?: UserRole[];
}

export interface NavCategory {
  label: string;
  items: NavItem[];
  roles?: UserRole[];
}

// Tab types
export interface Tab {
  id: string;
  label: string;
  content?: React.ReactNode;
}

// PR Review types
export type ReviewStatus = 'pending' | 'approved' | 'changes_requested' | 'commented';
export type IssueSeverity = 'critical' | 'high' | 'medium' | 'low';
export type IssueStatus = 'open' | 'in_progress' | 'resolved' | 'closed';

export interface PullRequest {
  id: number;
  number: number;
  title: string;
  description: string;
  repository: string;
  author: string;
  status: ReviewStatus;
  created_at: string;
  updated_at: string;
  url: string;
}

export interface ReviewComment {
  id: number;
  author: string;
  content: string;
  created_at: string;
  line?: number;
  file?: string;
}

export interface Review {
  id: number;
  pull_request_id: number;
  pull_request: PullRequest;
  reviewer: string;
  status: ReviewStatus;
  comments: ReviewComment[];
  created_at: string;
  updated_at: string;
}

export interface Issue {
  id: number;
  title: string;
  description: string;
  repository: string;
  severity: IssueSeverity;
  status: IssueStatus;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  url: string;
}

export interface RepositoryConfig {
  id: number;
  name: string;
  url: string;
  access_token?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  display_name?: string;
  repository?: string;
  platform?: string;
  platform_organization?: string;
  enabled?: boolean;
  polling_enabled?: boolean;
  polling_interval_minutes?: number;
  auto_review?: boolean;
}

export interface ReviewMetrics {
  total_reviews: number;
  approved: number;
  changes_requested: number;
  pending: number;
  avg_review_time: number;
  total_issues: number;
  critical_issues: number;
  recent_activity: Array<{ date: string; count: number }>;
}

// Dashboard types (inferred from usage in Dashboard.tsx)
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

export type FindingSeverity = 'critical' | 'major' | 'minor' | 'suggestion';
export type Platform = string;

export interface DashboardStats {
  overview: {
    total_repositories: number;
    total_reviews: number;
    pending_reviews: number;
  };
  findings: Record<FindingSeverity, number>;
  platforms: Record<Platform, number>;
}

export interface FindingsResponse {
  findings: Finding[];
  pagination: { total: number; pages: number };
}

export interface DashboardFilters {
  platform?: Platform;
  organization?: string;
  severity?: FindingSeverity;
  repository_id?: string;
}

// Repository types
export type Repository = RepositoryConfig;
export interface CreateRepositoryData {
  name: string;
  url: string;
  access_token: string;
}
export interface UpdateRepositoryData {
  url?: string;
  access_token?: string;
  is_active?: boolean;
}
export interface RepositoryListResponse {
  items?: RepositoryConfig[];
  repositories?: RepositoryConfig[];
  total?: number;
  page?: number;
  per_page?: number;
  pages?: number;
  pagination?: { total: number; pages: number };
  [key: string]: any;
}
export interface OrganizationsResponse {
  organizations: string[];
}

// Team & Tenant types
export interface Team {
  id: number;
  name: string;
  description?: string;
  slug?: string;
  is_default?: boolean;
  member_count?: number;
  created_at: string;
  updated_at: string;
}

export interface TeamMember {
  id: number;
  user_id: number;
  team_id: number;
  role: UserRole;
  user?: { id: number; email: string; full_name: string };
  created_at: string;
}

export interface Tenant {
  id: number;
  name: string;
  slug: string;
  description?: string;
  is_active: boolean;
  member_count?: number;
  team_count?: number;
  created_at: string;
  updated_at: string;
}

export interface TenantMember {
  id: number;
  user_id: number;
  tenant_id: number;
  role: UserRole;
  user?: { id: number; email: string; full_name: string };
  created_at: string;
}

// Role & Scope types
export interface Role {
  id: number;
  name: string;
  description?: string;
  scopes: Scope[];
  slug?: string;
  level?: string;
  is_active?: boolean;
  scope_count?: number;
  created_at: string;
  updated_at: string;
  [key: string]: any;
}

export interface Scope {
  id: number;
  name: string;
  category: string;
  description?: string;
  slug?: string;
  [key: string]: any;
}
