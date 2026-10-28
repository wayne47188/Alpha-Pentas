-- Bind verified client certificates to authoritative operator identities.
BEGIN;
CREATE TABLE operator_identities (
  certificate_sha256 bytea PRIMARY KEY CHECK (octet_length(certificate_sha256)=32),
  operator_id text NOT NULL CHECK (length(operator_id) BETWEEN 1 AND 200),
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked')),
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CHECK (
    (state='active' AND revoked_at IS NULL) OR
    (state='revoked' AND revoked_at IS NOT NULL)
  )
);
CREATE INDEX operator_identities_active_operator_idx
  ON operator_identities(operator_id,tenant_id)
  WHERE state='active' AND revoked_at IS NULL;
COMMIT;
