// Darwin AI Code Review - TypeScript types

export type DarwinProvider = 'github' | 'gitlab';
export type DarwinReviewStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type DarwinPlanStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type DarwinAIProvider = 'anthropic' | 'openai' | 'ollama';
export type DarwinSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Repository configuration
export interface DarwinRepo {
  id: number;
  tenant_id?: number;
  provider: DarwinProvider;
  repo_url: string;
  repo_name: string;
  auto_review: boolean;
  is_active: boolean;
  created_at: string;
}

export interface DarwinRepoCreateRequest {
  provider: DarwinProvider;
  repo_url: string;
  repo_name: string;
  webhook_secret?: string;
  auto_review?: boolean;
  is_active?: boolean;
}

export interface DarwinRepoUpdateRequest extends Partial<DarwinRepoCreateRequest> {}

// Review comment
export interface DarwinReviewComment {
  id: number;
  review_id: number;
  file_path: string;
  line_number?: number;
  comment: string;
  severity: DarwinSeverity;
  created_at: string;
}

// Code review
export interface DarwinReview {
  id: number;
  repo_config_id: number;
  repo_name?: string;
  pr_number?: number;
  pr_url?: string;
  status: DarwinReviewStatus;
  ai_provider?: DarwinAIProvider;
  model?: string;
  summary?: string;
  completed_at?: string;
  created_at: string;
  comments?: DarwinReviewComment[];
}

export interface DarwinReviewCreateRequest {
  repo_config_id: number;
  pr_number?: number;
  pr_url?: string;
  ai_provider?: DarwinAIProvider;
  model?: string;
}

// Issue plan
export interface DarwinPlan {
  id: number;
  repo_config_id: number;
  repo_name?: string;
  issue_number?: number;
  issue_url?: string;
  plan_content?: string;
  ai_provider?: DarwinAIProvider;
  status: DarwinPlanStatus;
  created_at: string;
}

export interface DarwinPlanCreateRequest {
  repo_config_id: number;
  issue_number?: number;
  issue_url?: string;
  ai_provider?: DarwinAIProvider;
}

// Service status
export interface DarwinStatus {
  status: string;
  version?: string;
  celery_workers?: number;
  queues?: Record<string, number>;
}

// License info returned in 403 bodies
export interface DarwinLicenseError {
  error: string;
}
