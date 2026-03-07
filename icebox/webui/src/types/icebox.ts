// IceBox shared TypeScript types

export type SecretType =
  | 'api_key'
  | 'db_password'
  | 'token'
  | 'cloud_credential'
  | 'service_account'
  | 'certificate'
  | 'ssh_key'
  | 'one_time';

export interface Secret {
  id: string;
  name: string;
  description: string;
  secret_type: SecretType;
  current_version_id: string | null;
  tags: Record<string, string>;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
}

export interface SecretVersion {
  id: string;
  secret_id: string;
  version_number: number;
  created_by: string;
  created_at: string;
  deprecated_at: string | null;
}

export type JitStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'revoked';

export interface JitRequest {
  id: string;
  secret_id: string;
  secret_name?: string;
  requestor_id: string;
  reason: string;
  requested_duration_seconds: number;
  approved_duration_seconds: number | null;
  status: JitStatus;
  approved_by: string | null;
  approved_at: string | null;
  access_expires_at: string | null;
  created_at: string;
}

export interface OneTimeSecret {
  id: string;
  url_token?: string;
  view_url?: string;
  viewed_at: string | null;
  expires_at: string;
  created_by: string;
}

export type CloudProvider = 'aws' | 'azure' | 'gcp' | 'oracle' | 'kubernetes';
export type SyncDirection = 'icebox_to_cloud' | 'cloud_to_icebox' | 'bidirectional';

export interface CloudIntegration {
  id: string;
  provider: CloudProvider;
  name: string;
  description: string;
  sync_direction: SyncDirection;
  sync_scopes: string[];
  enabled: boolean;
  last_sync_at: string | null;
  created_at: string;
}

export interface AuditEntry {
  id: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip_address: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface LicenseInfo {
  valid: boolean;
  license_key_masked: string | null;
  entitlements: string[];
  validated_at: string | null;
  license_server_url: string;
}

export interface AuthUser {
  id: string;
  email: string;
  scopes: string[];
  roles: string[];
  tenant: string;
}

export interface ApiResponse<T> {
  status: 'success' | 'error';
  data?: T;
  message?: string;
  meta?: {
    version: number;
    timestamp: string;
    total?: number;
    page?: number;
    per_page?: number;
  };
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
}
