-- Persist public certificates for idempotent claim retries.
-- Multiple nonrevoked certificates per Agent are permitted during key rotation.
BEGIN;
ALTER TABLE agent_certificates ADD COLUMN IF NOT EXISTS certificate_der bytea;
ALTER TABLE enrollment_claims ADD COLUMN IF NOT EXISTS certificate_id uuid UNIQUE REFERENCES agent_certificates(id);
CREATE INDEX IF NOT EXISTS agent_certificates_agent_idx ON agent_certificates(agent_id);
COMMIT;
