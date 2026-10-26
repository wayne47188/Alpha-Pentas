-- P1 CENTRAL manager-side schema. Never deployed on Agent.
-- Postgres 15+ recommended. Enforce API/RBAC ownership checks separately.
BEGIN;

CREATE TABLE IF NOT EXISTS tenants (
 id uuid PRIMARY KEY,
 name text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
 id uuid PRIMARY KEY,
 tenant_id uuid NOT NULL REFERENCES tenants(id),
 name text NOT NULL,
 status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','closed')),
 created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agents (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 identity_public_key bytea,
 state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','active','suspended','revoked','expired')),
 enrolled_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (id, project_id)
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
 id uuid PRIMARY KEY,
 project_id uuid NOT NULL REFERENCES projects(id),
 token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
 expires_at timestamptz NOT NULL,
 consumed_at timestamptz,
 issued_by text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX IF NOT EXISTS enrollment_tokens_expiry_idx ON enrollment_tokens(expires_at);

CREATE TABLE IF NOT EXISTS agent_certificates (
 id uuid PRIMARY KEY,
 agent_id uuid NOT NULL REFERENCES agents(id),
 issuer_key_id text NOT NULL,
 serial_number text NOT NULL,
 sha256_fingerprint bytea NOT NULL UNIQUE CHECK(octet_length(sha256_fingerprint) = 32),
 not_before timestamptz NOT NULL,
 not_after timestamptz NOT NULL,
 revoked_at timestamptz,
 CHECK (not_after > not_before),
 UNIQUE(issuer_key_id, serial_number)
);

CREATE TABLE IF NOT EXISTS identity_audit (
 id uuid PRIMARY KEY,
 agent_id uuid REFERENCES agents(id),
 project_id uuid REFERENCES projects(id),
 event_type text NOT NULL,
 actor text NOT NULL,
 occurred_at timestamptz NOT NULL DEFAULT now(),
 event_sha256 bytea NOT NULL CHECK(octet_length(event_sha256)=32)
);
COMMIT;

-- Enrollment redemption: start a transaction, SELECT ... FOR UPDATE,
-- validate token project/expiry/unconsumed and atomically mark consumed.
-- Do not grant certificates solely because a token record exists.
