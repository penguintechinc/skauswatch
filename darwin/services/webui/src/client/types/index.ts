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
}

export interface UpdateUserData {
  email?: string;
  full_name?: string;
  role?: UserRole;
  is_active?: boolean;
  password?: string;
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
