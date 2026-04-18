// Checkpoint sub-module types

export interface OAuthClient {
  id: string;
  client_id: string;
  name: string;
  description: string;
  redirect_uris: string[];
  allowed_scopes: string;
  grant_types: string[];
  require_pkce: boolean;
  is_active: boolean;
  created_at: string;
}

export interface OAuthClientCreated extends OAuthClient {
  client_secret: string; // Only returned on creation — show once
}

export interface SAMLProvider {
  id: string;
  entity_id: string;
  name: string;
  acs_url: string;
  metadata_url: string;
  is_active: boolean;
  created_at: string;
}

export interface UpstreamIDP {
  id: string;
  name: string;
  type: 'oidc' | 'saml' | 'ldap' | 'google' | 'okta';
  federation_mode: 'sync' | 'proxy';
  sync_interval_secs: number;
  is_active: boolean;
  last_sync_at: string | null;
  sync_error: string | null;
  created_at: string;
}

export interface LDAPAgent {
  agent_id: string;
  hostname: string;
  site_name: string;
  version: string;
  last_seen_at: string;
  status: 'online' | 'offline' | 'degraded';
}

export interface CheckpointAuditEntry {
  id: string;
  event_type: string;
  actor_uuid: string | null;
  actor_ip: string | null;
  target_uuid: string | null;
  target_type: string | null;
  client_id: string | null;
  scopes: string | null;
  created_at: string;
}

export interface SigningKey {
  kid: string;
  algorithm: string;
  is_active: boolean;
  grace_period_until: string | null;
  created_at: string;
  revoked_at: string | null;
}

export interface IdentityUser {
  uuid: string;
  email: string;
  display_name: string;
  given_name: string;
  family_name: string;
  status: 'active' | 'suspended' | 'pending';
  mfa_enabled: boolean;
  locale: string;
  created_at: string;
  last_login_at: string | null;
}

export interface IdentityGroup {
  uuid: string;
  name: string;
  display_name: string;
  description: string;
  type: 'local' | 'external';
  member_count: number;
  created_at: string;
}

export interface CheckpointConfig {
  token_ttl: number;
  refresh_token_ttl: number;
  require_pkce: boolean;
  auth_rate_limit_per_min: number;
  auth_rate_limit_per_hour: number;
  elder_push_enabled: boolean;
  elder_push_url: string;
}

export interface CheckpointPaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  per_page: number;
  pages: number;
}
