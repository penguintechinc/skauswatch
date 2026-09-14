-- Tenant isolation retrofit (docs/v2-port/tenancy-model.md). pki has no
-- local JWT/user table of its own, so tenant travels as the `X-Tenant-ID`
-- REST header / `x-tenant-id` gRPC metadata entry stamped by the calling
-- service (manager) — see src/tenant.rs. It is never accepted from a
-- client-supplied path/body/query field.
--
-- All 4 tables this service owns get a mandatory `tenant_id UUID`,
-- backfilled to the shared bootstrap-tenant literal used workspace-wide
-- (must match manager's seeded `tenants` row exactly — v2 has never shipped
-- to prod, so every existing row in every environment is backfilled the
-- same way, not carried forward from a real multi-tenant history).
--
-- No real FK to a `tenants` table: pki and manager do not share a
-- database (see tenancy-model.md §5, "logical reference, enforced by
-- application-level validation, not REFERENCES").

ALTER TABLE x509_certificates ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE x509_certificates SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE x509_certificates ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_x509_certificates_tenant_status ON x509_certificates (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_x509_certificates_tenant_not_after ON x509_certificates (tenant_id, not_after);

ALTER TABLE ssh_certificates ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE ssh_certificates SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE ssh_certificates ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ssh_certificates_tenant_status ON ssh_certificates (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_ssh_certificates_tenant_valid_before ON ssh_certificates (tenant_id, valid_before);

-- crl_entries is polymorphic across both CAs; tenant_id is stamped from the
-- same caller-provided tenant that owned the certificate being revoked (see
-- CertManager::revoke_x509/revoke_ssh), not re-derived from the parent row.
ALTER TABLE crl_entries ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE crl_entries SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE crl_entries ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_crl_entries_tenant_certificate_type ON crl_entries (tenant_id, certificate_type);

ALTER TABLE pki_audit_log ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE pki_audit_log SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE pki_audit_log ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pki_audit_log_tenant_timestamp ON pki_audit_log (tenant_id, timestamp DESC);
