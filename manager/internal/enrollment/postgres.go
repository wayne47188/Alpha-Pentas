package enrollment

import (
 "context"
 "crypto/rand"
 "crypto/sha256"
 "database/sql"
 "encoding/base64"
 "errors"
 "time"
)

// SQLStore stores token metadata centrally; the caller supplies an opened
// PostgreSQL database/sql connection. No DB runs inside the endpoint Agent.
type SQLStore struct { DB *sql.DB }

// IssueToken persists a single-use token digest. Never log or persist raw.
func (s SQLStore) IssueToken(ctx context.Context, tokenID, projectID, issuer string, ttl time.Duration) (string, error) {
 if s.DB == nil { return "",errors.New("nil database") }
 if tokenID=="" || projectID=="" || issuer=="" || ttl<=0 || ttl>time.Hour { return "",errors.New("invalid enrollment parameters") }
 secret:=make([]byte,32)
 if _,err:=rand.Read(secret);err!=nil{return "",err}
 raw:=base64.RawURLEncoding.EncodeToString(secret)
 digest:=sha256.Sum256([]byte(raw))
 // The DB clock controls expiration, not the possibly-skewed API clock.
 _,err:=s.DB.ExecContext(ctx,`INSERT INTO enrollment_tokens
 (id, project_id, token_digest, expires_at, issued_by)
 VALUES ($1, $2, $3, now() + ($4 * interval '1 second'), $5)`,
 tokenID,projectID,digest[:],int64(ttl.Seconds()),issuer)
 if err!=nil{return "",err}
 return raw,nil
}

// ConsumeToken executes a single conditional UPDATE. PostgreSQL row locking
// guarantees one winner, even across multiple Manager replicas.
// Wrong-project claims do not consume the token.
func (s SQLStore) ConsumeToken(ctx context.Context, raw, projectID string) error {
 if s.DB==nil { return errors.New("nil database") }
 if raw=="" || projectID=="" { return ErrInvalid }
 digest:=sha256.Sum256([]byte(raw))
 var id string
 err:=s.DB.QueryRowContext(ctx,`UPDATE enrollment_tokens SET consumed_at = now()
 WHERE token_digest = $1 AND project_id = $2
 AND consumed_at IS NULL AND expires_at > now()
 RETURNING id`,digest[:],projectID).Scan(&id)
 if errors.Is(err,sql.ErrNoRows) {return ErrInvalid}
 return err
}
