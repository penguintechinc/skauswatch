// CodeScan AI Code Review - TypeScript types

export type CodeScanProvider = 'github' | 'gitlab';
export type CodeScanReviewStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type CodeScanPlanStatus = 'pending' | 'processing' | 'completed' | 'failed';
export type CodeScanAIProvider = 'anthropic' | 'openai' | 'ollama';
export type CodeScanSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Repository configuration
export interface CodeScanRepo {
  id: number;
  tenant_id?: number;
  provider: CodeScanProvider;
  repo_url: string;
  repo_name: string;
  auto_review: boolean;
  is_active: boolean;
  created_at: string;
}

export interface CodeScanRepoCreateRequest {
  provider: CodeScanProvider;
  repo_url: string;
  repo_name: string;
  webhook_secret?: string;
  auto_review?: boolean;
  is_active?: boolean;
}

export interface CodeScanRepoUpdateRequest extends Partial<CodeScanRepoCreateRequest> {}

// Review comment
export interface CodeScanReviewComment {
  id: number;
  review_id: number;
  file_path: string;
  line_number?: number;
  comment: string;
  severity: CodeScanSeverity;
  created_at: string;
}

// Code review
export interface CodeScanReview {
  id: number;
  repo_config_id: number;
  repo_name?: string;
  pr_number?: number;
  pr_url?: string;
  status: CodeScanReviewStatus;
  ai_provider?: CodeScanAIProvider;
  model?: string;
  summary?: string;
  completed_at?: string;
  created_at: string;
  comments?: CodeScanReviewComment[];
}

export interface CodeScanReviewCreateRequest {
  repo_config_id: number;
  pr_number?: number;
  pr_url?: string;
  ai_provider?: CodeScanAIProvider;
  model?: string;
}

// Issue plan
export interface CodeScanPlan {
  id: number;
  repo_config_id: number;
  repo_name?: string;
  issue_number?: number;
  issue_url?: string;
  plan_content?: string;
  ai_provider?: CodeScanAIProvider;
  status: CodeScanPlanStatus;
  created_at: string;
}

export interface CodeScanPlanCreateRequest {
  repo_config_id: number;
  issue_number?: number;
  issue_url?: string;
  ai_provider?: CodeScanAIProvider;
}

// Service status
export interface CodeScanStatus {
  status: string;
  version?: string;
  celery_workers?: number;
  queues?: Record<string, number>;
}

// License info returned in 403 bodies
export interface CodeScanLicenseError {
  error: string;
}
