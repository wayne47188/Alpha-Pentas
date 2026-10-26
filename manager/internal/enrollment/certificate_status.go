package enrollment

import (
	"context"
	"crypto/sha256"
	"errors"
)

// CertificateStatus is the authoritative Manager-side revocation and state
// check used by identity.VerifyAgentPeer after TLS chain verification.
// It does not grant operator authorization for commands or evidence access.
func (s SQLStore) CertificateStatus(ctx context.Context, projectID, agentID string, fingerprint [32]byte) error {
	if s.DB == nil {
		return errors.New("nil database")
	}
	if projectID == "" || agentID == "" || fingerprint == (sha256.Sum256(nil)) {
		return ErrInvalid
	}
	var active bool
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS (
 SELECT 1 FROM agent_certificates c
 JOIN agents a ON a.id=c.agent_id
 JOIN projects p ON p.id=a.project_id
 JOIN enrollment_claims ec ON ec.certificate_id=c.id
 WHERE a.id=$1 AND a.project_id=$2
 AND a.state='active' AND p.status='active'
 AND ec.state='issued' AND ec.agent_id=a.id AND ec.project_id=p.id
 AND c.sha256_fingerprint=$3
 AND c.revoked_at IS NULL
 AND c.not_before<=now() AND c.not_after>now()
 )`, agentID, projectID, fingerprint[:]).Scan(&active)
	if err != nil {
		return err
	}
	if !active {
		return ErrInvalid
	}
	return nil
}
