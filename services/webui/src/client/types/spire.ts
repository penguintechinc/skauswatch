/**
 * SPIRE API Types
 * TypeScript interfaces for SPIRE service REST API endpoints
 */

/**
 * Health status of the SPIRE server
 */
export interface SpireStatus {
  healthy: boolean;
  uptime: string;
  spiffe_endpoint: string;
  agents_connected: number;
  active_svids: number;
}

/**
 * SPIFFE selector for identity entries
 */
export interface Selector {
  type: string;
  value: string;
}

/**
 * SPIFFE identity entry
 */
export interface SpireEntry {
  id: string;
  spiffe_id: string;
  parent_id: string;
  selectors: Selector[];
  ttl: number;
  admin: boolean;
  downstream: boolean;
  expires_at: string | null;
}

/**
 * Response for GET /entries
 */
export interface SpireEntriesResponse {
  entries: SpireEntry[];
}

/**
 * Request body for POST /entries
 */
export interface CreateEntryRequest {
  spiffe_id: string;
  parent_id: string;
  selectors: Selector[];
  ttl?: number;
}

/**
 * Response for POST /entries
 */
export interface CreateEntryResponse extends SpireEntry {}

/**
 * Response for DELETE /entries/<id>
 */
export interface DeleteEntryResponse {
  message: string;
}

/**
 * SPIRE node (agent)
 */
export interface SpireNode {
  id: string;
  spiffe_id: string;
  attestation_type: string;
  banned: boolean;
  expires_at: string;
}

/**
 * Response for GET /nodes
 */
export interface SpireNodesResponse {
  nodes: SpireNode[];
}

/**
 * Request body for POST /nodes/join-token
 */
export interface CreateJoinTokenRequest {
  ttl?: number; // seconds (default 600)
}

/**
 * Response for POST /nodes/join-token
 */
export interface CreateJoinTokenResponse {
  token: string;
  expires_at: string;
}

/**
 * Trust domain bundle for federation
 */
export interface TrustDomainBundle {
  trust_domain: string;
  sequence_number: number;
  refresh_hint: number;
}

/**
 * Response for GET /federation
 */
export interface SpireFederationResponse {
  bundles: TrustDomainBundle[];
}

/**
 * Request body for POST /federation/peers
 */
export interface CreateFederationPeerRequest {
  trust_domain: string;
  endpoint_url: string;
}

/**
 * Response for POST /federation/peers
 */
export interface CreateFederationPeerResponse {
  message: string;
}

/**
 * Response for DELETE /federation/peers/<trust_domain>
 */
export interface DeleteFederationPeerResponse {
  message: string;
}

/**
 * Datastore type for migration
 */
export type DatastoreType = 'sqlite' | 'postgresql';

/**
 * Request body for POST /datastore/migrate
 */
export interface DatastoreMigrateRequest {
  type: DatastoreType;
  host?: string;
  port?: number;
  db_name?: string;
  secret_name?: string;
}

/**
 * Response for POST /datastore/migrate
 */
export interface DatastoreMigrateResponse {
  message: string;
}
