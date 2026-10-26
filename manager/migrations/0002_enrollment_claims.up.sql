-- Atomic token claim + Agent identity reservation. Manager-only.
BEGIN;
CREATE TABLE IF NOT EXISTS enrollment_claims (
 id uuid PRIMARY KEY,
 token_id uuid NOT NULL UNIQUE REFERENCES enrollment_tokens(id),
 project_id uuid NOT NULL REFERENCES projects(id),
 agent_id uuid NOT NULL UNIQUE,
 csr_sha256 bytea NOT NULL CHECK (octet_length(csr_sha256) = 32),
 state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','issued','failed','revoked')),
 created_at timestamptz NOT NULL DEFAULT now(),
 issued_at timestamptz,
 UNIQUE (agent_id, project_id),
 FOREIGN KEY (agent_id, project_id) REFERENCES agents(id, project_id)
);
CREATE INDEX IF NOT EXISTS enrollment_claims_project_state_idx ON enrollment_claims(project_id,state);
COMMIT;
