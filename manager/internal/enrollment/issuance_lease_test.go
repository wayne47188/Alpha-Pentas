package enrollment

import (
 "context"
 "crypto"
 "crypto/x509"
 "database/sql"
 "errors"
 "io"
 "os"
 "sync"
 "testing"
 "time"

 _ "github.com/lib/pq"
)

type blockingSigner struct {
 crypto.Signer
 entered chan struct{}
 release chan struct{}
 once sync.Once
}

func (s *blockingSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte,error) {
 s.once.Do(func(){close(s.entered)})
 <-s.release
 return s.Signer.Sign(random,digest,opts)
}

// A stalled CA must not keep the claim row locked; a concurrent attempt must
// return ErrClaimBusy promptly, not consume a connection waiting for signing.
func TestPostgresSigningDoesNotHoldRowLock(t *testing.T) {
 dsn:=os.Getenv("ALPHA_TEST_DATABASE_URL")
 if dsn==""{t.Skip("requires disposable PostgreSQL")}
 db,err:=sql.Open("postgres",dsn);if err!=nil{t.Fatal(err)}
 defer db.Close()
 db.SetMaxOpenConns(4)
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
 tenant,project,claim:=randomUUID(t),randomUUID(t),randomUUID(t)
 for _,v:=range []struct{q string; a []any}{
  {"INSERT INTO tenants(id,name) VALUES($1,'lease-test')",[]any{tenant}},
  {"INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,'lease-test')",[]any{project,tenant}},
 }{if _,err=db.ExecContext(ctx,v.q,v.a...);err!=nil{t.Fatal(err)}}
 issuer,csr:=testIssuer(t)
 token,err:=(SQLStore{DB:db}).IssueToken(ctx,randomUUID(t),project,"test",time.Minute)
 if err!=nil{t.Fatal(err)}
 // Claim creates a new agent, so use fresh identity rather than the fixture row.
 claimant:=randomUUID(t)
 if err:=(SQLStore{DB:db}).Claim(ctx,token,project,claimant,claim,csr);err!=nil{t.Fatal(err)}
 key:=&blockingSigner{Signer:issuer.Signer,entered:make(chan struct{}),release:make(chan struct{})}
 issuer.Signer=key
 result:=make(chan error,1)
 go func(){_,e:=(SQLStore{DB:db}).IssueClaim(ctx,claim,project,randomUUID(t),"CA-test",csr,issuer);result<-e}()
 select {
 case <-key.entered:
 case <-time.After(3*time.Second):t.Fatal("signer was not reached")
 }
 start:=time.Now()
 fastCtx,stop:=context.WithTimeout(ctx,2*time.Second)
 defer stop()
 _,busy:=(SQLStore{DB:db}).IssueClaim(fastCtx,claim,project,randomUUID(t),"CA-test",csr,issuer)
 if !errors.Is(busy,ErrClaimBusy){t.Errorf("concurrent claim = %v, want ErrClaimBusy",busy)}
 if time.Since(start)>time.Second{t.Error("a concurrent claim waited too long, suggesting a held row lock")}
 close(key.release)
 select {
 case err:=<-result: if err!=nil{t.Fatal(err)}
 case <-time.After(5*time.Second):t.Fatal("signer completion hung")
 }
 // The returned certificate must be idempotent while active.
 other,err:=(SQLStore{DB:db}).IssueClaim(ctx,claim,project,randomUUID(t),"CA-test",csr,issuer)
 if err!=nil{t.Fatal(err)}
 if _,err=x509.ParseCertificate(other.CertificateDER);err!=nil{t.Fatal(err)}
 // Prevent unused import regressions.
}
