// Enums
export type S3ScanJobType = 'scheduled' | 'manual' | 'realtime';
export type S3ScanJobStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled';
export type S3ScanStatus =
  | 'clean'
  | 'infected'
  | 'pup'
  | 'error'
  | 'skipped';
export type SandboxStatus = 'pending' | 'running' | 'completed' | 'failed';

// Threat Intelligence Enrichment
export interface TIEnrichment {
  vt_score?: number;
  vt_total?: number;
  otx_pulses?: number;
  threat_family?: string;
  severity?: string;
  related_iocs?: string[];
}

// Bucket configuration
export interface BucketConfig {
  id: number;
  name: string;
  endpoint_url: string;
  bucket_name: string;
  access_key_id: string;
  secret_access_key_masked: string; // Masked for display
  region: string;
  use_ssl: boolean;
  path_style: boolean;
  prefix_filter?: string;
  file_types_filter?: string[];
  max_file_size_mb: number;
  scan_enabled: boolean;
  yara_enabled: boolean;
  created_by: number;
  created_at: string;
  updated_at?: string;
}

// Create/Update bucket request
export interface BucketConfigCreateRequest {
  name: string;
  endpoint_url: string;
  bucket_name: string;
  access_key_id: string;
  secret_access_key: string;
  region?: string;
  use_ssl?: boolean;
  path_style?: boolean;
  prefix_filter?: string;
  file_types_filter?: string[];
  max_file_size_mb?: number;
  scan_enabled?: boolean;
  yara_enabled?: boolean;
}

export interface BucketConfigUpdateRequest
  extends Partial<BucketConfigCreateRequest> {}

// Scan job
export interface ScanJob {
  id: number;
  job_id: string;
  bucket_config_id: number;
  bucket_name?: string;
  job_type: S3ScanJobType;
  status: S3ScanJobStatus;
  total_objects: number;
  scanned_objects: number;
  infected_objects: number;
  pup_objects: number;
  skipped_objects: number;
  error_count: number;
  progress_percent?: number;
  started_at?: string;
  completed_at?: string;
  triggered_by: number;
  error_message?: string;
  created_at: string;
}

// Scan result
export interface ScanResult {
  id: number;
  job_id: string;
  bucket_config_id: number;
  object_key: string;
  object_size: number;
  object_etag?: string;
  content_type?: string;
  detected_file_type?: string;
  scan_status: S3ScanStatus;
  is_malware: boolean;
  is_pup: boolean;
  is_threat: boolean;
  threat_names: string[];
  clamav_result?: Record<string, unknown>;
  yara_matches?: Record<string, unknown>[];
  file_md5?: string;
  file_sha1?: string;
  file_sha256?: string;
  ti_enrichment?: TIEnrichment;
  sandbox_submitted: boolean;
  sandbox_result?: Record<string, unknown>;
  scan_duration_ms?: number;
  tags_applied: boolean;
  scanned_at: string;
}

// Ad-hoc scan
export interface AdhocScanResult {
  id: number;
  scan_id: string;
  uploaded_by: number;
  original_filename: string;
  file_size: number;
  content_type?: string;
  detected_file_type?: string;
  scan_status: S3ScanStatus;
  is_malware: boolean;
  is_pup: boolean;
  is_threat: boolean;
  threat_names: string[];
  file_md5?: string;
  file_sha256?: string;
  ti_enrichment?: TIEnrichment;
  scan_duration_ms?: number;
  uploaded_at: string;
  scanned_at?: string;
}

// Schedule
export interface ScanSchedule {
  id: number;
  bucket_config_id: number;
  cron_expression: string;
  timezone: string;
  enabled: boolean;
  last_run_at?: string;
  next_run_at?: string;
  created_at: string;
  updated_at?: string;
}

// Bucket statistics
export interface BucketStats {
  total: number;
  infected: number;
  clean: number;
}

// Statistics
export interface ScanStatistics {
  total_scanned: number;
  total_infected: number;
  total_pup: number;
  total_clean: number;
  total_error: number;
  by_file_type: Record<string, number>;
  by_bucket: Record<string, BucketStats>;
}

// Pagination
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}

// Connection test
export interface ConnectionTestResult {
  success: boolean;
  message: string;
  bucket_exists?: boolean;
  object_count?: number;
}

// Query params for results
export interface ScanResultsQuery {
  bucket_config_id?: number;
  scan_status?: S3ScanStatus[];
  is_malware?: boolean;
  is_pup?: boolean;
  is_threat?: boolean;
  file_type?: string;
  date_from?: string;
  date_to?: string;
  page?: number;
  per_page?: number;
}

// Indicator creation response
export interface IndicatorCreateResponse {
  indicator_id: number;
}
