-- Durable signing reservation: CA operations must happen OUTSIDE DB locks.
BEGIN;
ALTER TABLE enrollment_claims DROP CONSTRAINT IF EXISTS enrollment_claims_state_check;
ALTER TABLE enrollment_claims ADD CONSTRAINT enrollment_claims_state_check CHECK (state IN ('pending','issuing','issued','failed','revoked'));
ALTER TABLE enrollment_claims ADD COLUMN IF NOT EXISTS lease_owner uuid;
ALTER TABLE enrollment_claims ADD COLUMN IF NOT EXISTS lease_expires_at timestamptz;
ALTER TABLE enrollment_claims ADD COLUMN IF NOT EXISTS issuance_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE enrollment_claims ADD CONSTRAINT enrollment_claims_lease_pair_check CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL));
CREATE INDEX IF NOT EXISTS enrollment_claims_issuing_expiration ON enrollment_claims(lease_expires_at) WHERE state='issuing';
COMMIT;
