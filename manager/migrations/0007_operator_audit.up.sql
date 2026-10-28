-- Durable security audit for operator API authorization/rate-limit denials.
BEGIN;
CREATE TABLE operator_audit (
  id bigserial PRIMARY KEY,
  operator_id text,
  tenant_id uuid REFERENCES tenants(id),
  project_ref text NOT NULL DEFAULT '' CHECK (length(project_ref) <= 200),
  event_type text NOT NULL CHECK (event_type IN ('authorization_denied')),
  reason text NOT NULL CHECK (reason IN ('unauthenticated','missing_project','rate_limited','forbidden')),
  occurred_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX operator_audit_occurred_idx ON operator_audit(occurred_at DESC);
CREATE INDEX operator_audit_operator_idx ON operator_audit(operator_id,occurred_at DESC)
  WHERE operator_id IS NOT NULL;
COMMIT;
