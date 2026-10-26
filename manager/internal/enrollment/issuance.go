package enrollment

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

var ErrClaimNotPending = errors.New("claim is not eligible for issuance")

// IssuanceResult exposes only public certificate bytes, never a private key.
type IssuanceResult struct {
	CertificateDER []byte
	Serial         string
}

// IssueClaim holds the claim row lock while verifying the stored CSR hash,
// signing and committing the issued certificate. Retrying an issued claim
// retrieves its persisted public cert; a different CSR is always rejected.
// Signer operations must have a bounded timeout in a production worker.
func (s SQLStore) IssueClaim(ctx context.Context, claimID, projectID, certID, issuerKeyID string, csrDER []byte, issuer identity.Issuer) (IssuanceResult, error) {
	var out IssuanceResult
	if s.DB == nil {
		return out, errors.New("nil database")
	}
	if claimID == "" || projectID == "" || certID == "" || issuerKeyID == "" || len(csrDER) == 0 {
		return out, ErrInvalid
	}
	if _, err := identity.ValidateCSR(csrDER); err != nil {
		return out, err
	}
	digest := sha256.Sum256(csrDER)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var agentID, state string
	var storedDigest []byte
	var existingCertID sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT agent_id,state,csr_sha256,certificate_id FROM enrollment_claims
 WHERE id=$1 AND project_id=$2 FOR UPDATE`, claimID, projectID).Scan(&agentID, &state, &storedDigest, &existingCertID)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrInvalid
	}
	if err != nil {
		return out, err
	}
	if len(storedDigest) != len(digest) || subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
		return out, ErrInvalid
	}
	if state == "issued" && existingCertID.Valid {
		err = tx.QueryRowContext(ctx, `SELECT certificate_der,serial_number FROM agent_certificates
 WHERE id=$1 AND agent_id=$2 AND revoked_at IS NULL`, existingCertID.String, agentID).Scan(&out.CertificateDER, &out.Serial)
		if err != nil {
			return out, err
		}
		return out, tx.Commit()
	}
	if state != "pending" {
		return out, ErrClaimNotPending
	}
	issued, err := issuer.Issue(csrDER, projectID, agentID, 7*24*time.Hour)
	if err != nil {
		return out, fmt.Errorf("sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(issued.CertificateDER)
	if err != nil {
		return out, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO agent_certificates
 (id,agent_id,issuer_key_id,serial_number,sha256_fingerprint,not_before,not_after,certificate_der)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, certID, agentID, issuerKeyID, issued.Serial, issued.Fingerprint[:], cert.NotBefore, cert.NotAfter, issued.CertificateDER)
	if err != nil {
		return out, err
	}
	claimUpdate, err := tx.ExecContext(ctx, `UPDATE enrollment_claims SET state='issued',issued_at=now(),certificate_id=$2
 WHERE id=$1 AND state='pending'`, claimID, certID)
	if err != nil {
		return out, err
	}
	claimRows, err := claimUpdate.RowsAffected()
	if err != nil {
		return out, err
	}
	if claimRows != 1 {
		return out, ErrClaimNotPending
	}
	agentUpdate, err := tx.ExecContext(ctx, `UPDATE agents SET state='active',enrolled_at=now() WHERE id=$1 AND project_id=$2 AND state='pending'`, agentID, projectID)
	if err != nil {
		return out, err
	}
	agentRows, err := agentUpdate.RowsAffected()
	if err != nil {
		return out, err
	}
	if agentRows != 1 {
		return out, ErrClaimNotPending
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return IssuanceResult{CertificateDER: issued.CertificateDER, Serial: issued.Serial}, nil
}
