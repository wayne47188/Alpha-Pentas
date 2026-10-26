-- Retain the issued public certificate to recover lost enrollment responses.
BEGIN;
ALTER TABLE agent_certificates ADD COLUMN IF NOT EXISTS certificate_der bytea;
ALTER TABLE enrollment_claims ADD COLUMN IF NOT EXISTS certificate_id uuid UNIQUE REFERENCES agent_certificates(id);
CREATE UNIQUE INDEX IF NOT EXISTS agent_certificates_one_per_agent ON agent_certificates(agent_id)
 WHERE revoked_at IS NULL;
COMMIT;
