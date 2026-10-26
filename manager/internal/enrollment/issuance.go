package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

var ErrClaimNotPending = errors.New("claim is not eligible for issuance")
var ErrClaimBusy = errors.New("claim already has an active issuance lease")
var ErrLeaseLost = errors.New("issuance lease expired or superseded")

type IssuanceResult struct {
	CertificateDER []byte
	Serial         string
}

const issuanceLease = 45 * time.Second

// IssueClaim proves possession of the same one-time token that reserved the
// claim. A claim ID and public CSR are not sufficient enrollment authority.
// This is still an internal Manager primitive, not an authenticated HTTP API.
func (s SQLStore) IssueClaim(ctx context.Context, claimID, projectID, certID, issuerKeyID, rawToken string, csrDER []byte, issuer identity.Issuer) (IssuanceResult, error) {
	var empty IssuanceResult
	if s.DB == nil {
		return empty, errors.New("nil database")
	}
	if claimID == "" || projectID == "" || rawToken == "" || len(rawToken) > 256 {
		return empty, ErrInvalid
	}
	digest := sha256.Sum256([]byte(rawToken))
	var stored []byte
	err := s.DB.QueryRowContext(ctx, `SELECT t.token_digest
 FROM enrollment_claims ec JOIN enrollment_tokens t ON t.id=ec.token_id
 WHERE ec.id=$1 AND ec.project_id=$2 AND t.project_id=$2 AND t.consumed_at IS NOT NULL`, claimID, projectID).Scan(&stored)
	if err != nil || len(stored) != len(digest) || subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return empty, ErrInvalid
	}
	return s.issueClaim(ctx, claimID, projectID, certID, issuerKeyID, csrDER, issuer)
}

func newLeaseID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:]), nil
}

// issueClaim follows a three-phase state machine:
// 1. atomic DB lease reservation; 2. CA signing OUTSIDE any DB transaction;
// 3. short DB transaction that validates the fencing lease and persists result.
// This is not a public API: caller authorization and identity proof are required.
func (s SQLStore) issueClaim(ctx context.Context, claimID, projectID, certID, issuerKeyID string, csrDER []byte, issuer identity.Issuer) (IssuanceResult, error) {
	var empty IssuanceResult
	if s.DB == nil {
		return empty, errors.New("nil database")
	}
	if s.SigningPool == nil {
		return empty, ErrSigningPool
	}
	if claimID == "" || projectID == "" || certID == "" || issuerKeyID == "" || len(csrDER) == 0 {
		return empty, ErrInvalid
	}
	if _, err := identity.ValidateCSR(csrDER); err != nil {
		return empty, err
	}
	digest := sha256.Sum256(csrDER)
	leaseID, err := newLeaseID()
	if err != nil {
		return empty, err
	}

	// UPDATE has a short-lived row lock only. Expired reservations can be
	// reclaimed, but a stale signer is fenced at finalization.
	var agentID string
	err = s.DB.QueryRowContext(ctx, `UPDATE enrollment_claims
 SET state='issuing',lease_owner=$4,lease_expires_at=now()+($5 * interval '1 second'),
 issuance_attempts=issuance_attempts+1
 WHERE id=$1 AND project_id=$2 AND csr_sha256=$3
 AND (state='pending' OR (state='issuing' AND lease_expires_at<now()))
 RETURNING agent_id`, claimID, projectID, digest[:], leaseID, int64(issuanceLease/time.Second)).Scan(&agentID)
	if errors.Is(err, sql.ErrNoRows) {
		return s.existingIssuance(ctx, claimID, projectID, digest)
	}
	if err != nil {
		return empty, fmt.Errorf("acquire issuance lease: %w", err)
	}

	// No DB lock is held during signing. A slow/failed signer cannot exhaust
	// the pool through lock wait chains. The lease fences late results.
	issued, err := s.SigningPool.Sign(ctx, func() (identity.Result, error) {
		return issuer.Issue(csrDER, projectID, agentID, 7*24*time.Hour)
	})
	if err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, _ = s.DB.ExecContext(cleanupCtx, `UPDATE enrollment_claims
 SET state='pending',lease_owner=NULL,lease_expires_at=NULL
 WHERE id=$1 AND project_id=$2 AND state='issuing' AND lease_owner=$3`, claimID, projectID, leaseID)
		return empty, fmt.Errorf("sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(issued.CertificateDER)
	if err != nil {
		return empty, err
	}

	// Bounded short transaction. Lock validates the reservation before inserts.
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	var currentAgent string
	var storedDigest []byte
	err = tx.QueryRowContext(ctx, `SELECT agent_id,csr_sha256 FROM enrollment_claims
 WHERE id=$1 AND project_id=$2 AND state='issuing'
 AND lease_owner=$3 AND lease_expires_at>now() FOR UPDATE`, claimID, projectID, leaseID).Scan(&currentAgent, &storedDigest)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, ErrLeaseLost
	}
	if err != nil {
		return empty, err
	}
	if currentAgent != agentID || len(storedDigest) != len(digest) || subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
		return empty, ErrInvalid
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO agent_certificates
 (id,agent_id,issuer_key_id,serial_number,sha256_fingerprint,not_before,not_after,certificate_der)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		certID, agentID, issuerKeyID, issued.Serial, issued.Fingerprint[:], cert.NotBefore, cert.NotAfter, issued.CertificateDER)
	if err != nil {
		return empty, err
	}
	claimUpdate, err := tx.ExecContext(ctx, `UPDATE enrollment_claims
 SET state='issued',issued_at=now(),certificate_id=$2,lease_owner=NULL,lease_expires_at=NULL
 WHERE id=$1 AND state='issuing' AND lease_owner=$3`, claimID, certID, leaseID)
	if err != nil {
		return empty, err
	}
	claimRows, err := claimUpdate.RowsAffected()
	if err != nil {
		return empty, err
	}
	if claimRows != 1 {
		return empty, ErrLeaseLost
	}
	agentUpdate, err := tx.ExecContext(ctx, `UPDATE agents SET state='active',enrolled_at=now()
 WHERE id=$1 AND project_id=$2 AND state='pending'`, agentID, projectID)
	if err != nil {
		return empty, err
	}
	agentRows, err := agentUpdate.RowsAffected()
	if err != nil {
		return empty, err
	}
	if agentRows != 1 {
		return empty, ErrClaimNotPending
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return IssuanceResult{CertificateDER: issued.CertificateDER, Serial: issued.Serial}, nil
}

func (s SQLStore) existingIssuance(ctx context.Context, claimID, projectID string, digest [32]byte) (IssuanceResult, error) {
	var result IssuanceResult
	var state, agentID string
	var storedDigest []byte
	var certificateID sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT state,agent_id,csr_sha256,certificate_id
 FROM enrollment_claims WHERE id=$1 AND project_id=$2`, claimID, projectID).Scan(&state, &agentID, &storedDigest, &certificateID)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrInvalid
	}
	if err != nil {
		return result, err
	}
	if len(storedDigest) != len(digest) || subtle.ConstantTimeCompare(storedDigest, digest[:]) != 1 {
		return result, ErrInvalid
	}
	if state == "issuing" {
		return result, ErrClaimBusy
	}
	if state != "issued" || !certificateID.Valid {
		return result, ErrClaimNotPending
	}
	err = s.DB.QueryRowContext(ctx, `SELECT certificate_der,serial_number FROM agent_certificates
 WHERE id=$1 AND agent_id=$2 AND revoked_at IS NULL AND not_after>now()`, certificateID.String, agentID).Scan(&result.CertificateDER, &result.Serial)
	return result, err
}
