#!/usr/bin/env bash
set -euo pipefail

# Requires a disposable PostgreSQL database. NEVER point at a production DB.
: "${DATABASE_URL:?Set DATABASE_URL to a disposable PostgreSQL database URL}"
psql_safe() { psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -Atq "$@"; }
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

psql_safe -f manager/migrations/0001_identity.up.sql >/dev/null
psql_safe -f manager/migrations/0002_enrollment_claims.up.sql >/dev/null
psql_safe -f manager/migrations/0003_issued_certificates.up.sql >/dev/null

tenant="11111111-1111-4111-8111-111111111111"
project="22222222-2222-4222-8222-222222222222"
token="33333333-3333-4333-8333-333333333333"
psql_safe -c "INSERT INTO tenants(id,name) VALUES('$tenant','integration') ON CONFLICT(id) DO NOTHING"
psql_safe -c "INSERT INTO projects(id,tenant_id,name) VALUES('$project','$tenant','integration') ON CONFLICT(id) DO NOTHING"
# 32-byte digest, set in DB as hex to avoid moving a raw token.
psql_safe -c "INSERT INTO enrollment_tokens(id,project_id,token_digest,expires_at,issued_by)
VALUES ('$token','$project',decode(repeat('ab',32),'hex'),now()+interval '10 minutes','integration')
ON CONFLICT(id) DO UPDATE SET consumed_at=NULL, expires_at=now()+interval '10 minutes'"

# Each worker attempts to claim the *same* token, reserving separate agents
# and claims in one transaction. SQL rolls back on a failed reservation.
for n in $(seq 1 32); do
  agent=$(printf '44444444-4444-4444-8444-%012d' "$n")
  claim=$(printf '55555555-5555-4555-8555-%012d' "$n")
  (
    psql_safe -c "BEGIN;
WITH claimed AS (
 UPDATE enrollment_tokens SET consumed_at=now()
 WHERE id='$token' AND project_id='$project'
 AND consumed_at IS NULL AND expires_at>now()
 RETURNING id
), agent AS (
 INSERT INTO agents(id,project_id,state)
 SELECT '$agent'::uuid,'$project'::uuid,'pending' FROM claimed
 RETURNING id
)
INSERT INTO enrollment_claims(id,token_id,project_id,agent_id,csr_sha256)
SELECT '$claim'::uuid,'$token'::uuid,'$project'::uuid,agent.id,decode(repeat('cd',32),'hex') FROM agent;
COMMIT;" >"$workdir/$n.stdout" 2>"$workdir/$n.stderr"
  ) &
done
wait

claims=$(psql_safe -c "SELECT count(*) FROM enrollment_claims WHERE token_id='$token'")
agents=$(psql_safe -c "SELECT count(*) FROM agents WHERE project_id='$project'")
[[ "$claims" == "1" && "$agents" == "1" ]] || { echo "Expected one successful claim and one agent; claims=$claims agents=$agents"; exit 1; }
echo "PASS: 32 competing requests yielded exactly one claim and one agent."

# Rollback: reserve an existing agent ID after consuming another token.
token2="66666666-6666-4666-8666-666666666666"
existing=$(psql_safe -c "SELECT id FROM agents WHERE project_id='$project' LIMIT 1")
psql_safe -c "INSERT INTO enrollment_tokens(id,project_id,token_digest,expires_at,issued_by)
VALUES('$token2','$project',decode(repeat('ef',32),'hex'),now()+interval '10 minutes','integration')
ON CONFLICT(id) DO UPDATE SET consumed_at=NULL,expires_at=now()+interval '10 minutes'"
if psql_safe -c "BEGIN;
UPDATE enrollment_tokens SET consumed_at=now() WHERE id='$token2';
INSERT INTO agents(id,project_id) VALUES('$existing','$project');
COMMIT;" >/dev/null 2>&1; then
  echo "FAIL: duplicate Agent insertion unexpectedly succeeded"; exit 1
fi
consumed=$(psql_safe -c "SELECT consumed_at IS NULL FROM enrollment_tokens WHERE id='$token2'")
[[ "$consumed" == "t" ]] || { echo "FAIL: failed transaction consumed token"; exit 1; }
echo "PASS: failing Agent reservation rolled back token consumption."

# Project mismatch must not redeem a token.
other_project="77777777-7777-4777-8777-777777777777"
psql_safe -c "INSERT INTO projects(id,tenant_id,name) VALUES('$other_project','$tenant','unrelated') ON CONFLICT(id) DO NOTHING"
affected=$(psql_safe -c "WITH changed AS (UPDATE enrollment_tokens SET consumed_at=now()
WHERE id='$token2' AND project_id='$other_project' AND consumed_at IS NULL RETURNING id)
SELECT count(*) FROM changed")
[[ "$affected" == "0" ]] || { echo "FAIL: wrong-project redemption"; exit 1; }
echo "PASS: wrong project cannot redeem token."

# Expiry must be checked by PostgreSQL's clock.
psql_safe -c "UPDATE enrollment_tokens SET expires_at=now()-interval '1 second' WHERE id='$token2'"
affected=$(psql_safe -c "WITH changed AS (UPDATE enrollment_tokens SET consumed_at=now()
WHERE id='$token2' AND expires_at>now() AND consumed_at IS NULL RETURNING id)
SELECT count(*) FROM changed")
[[ "$affected" == "0" ]] || { echo "FAIL: expired token redeemed"; exit 1; }
echo "PASS: expired token cannot be redeemed."
