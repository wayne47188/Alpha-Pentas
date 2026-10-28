-- Authoritative operator grant records; not an authentication system.
BEGIN;
CREATE TABLE operator_grants (
  operator_id text NOT NULL,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  project_id uuid NOT NULL REFERENCES projects(id),
  action text NOT NULL CHECK (action IN ('enrollment.token.issue','enrollment.status.read','agent.manage')),
  revoked_at timestamptz,
  PRIMARY KEY (operator_id, tenant_id, project_id, action)
);
-- Prevent grants from referencing a project in a different tenant.
ALTER TABLE projects ADD CONSTRAINT projects_id_tenant_unique UNIQUE (id,tenant_id);
ALTER TABLE operator_grants ADD CONSTRAINT operator_grants_project_tenant_fk
  FOREIGN KEY (project_id,tenant_id) REFERENCES projects(id,tenant_id);
CREATE INDEX operator_grants_active_lookup ON operator_grants(operator_id,project_id,action) WHERE revoked_at IS NULL;
COMMIT;
