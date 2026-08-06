/**
 * SVID TTL Settings API Types
 * TypeScript interfaces for the super-admin SPIFFE SVID TTL control
 * (`GET/PUT /api/v1/admin/svid-ttl` on the manager backend).
 */

/**
 * Response for GET /admin/svid-ttl. `default_seconds`/`min_seconds`/
 * `max_seconds` are server-authoritative bounds — the client mirrors them
 * for validation but the server remains the source of truth (400 on a PUT
 * outside the bound).
 */
export interface SvidTtlSettings {
  x509_ttl_seconds: number;
  jwt_ttl_seconds: number;
  default_seconds: number;
  min_seconds: number;
  max_seconds: number;
}

/**
 * Request body for PUT /admin/svid-ttl.
 */
export interface UpdateSvidTtlRequest {
  x509_ttl_seconds: number;
  jwt_ttl_seconds: number;
}
