package enrollment

import (
 "context"
 "github.com/wayne47188/Alpha-Pentas/manager/internal/identity"
)

// ValidatedClaim verifies cryptographic CSR proof of possession and rejects
// caller-specified SANs before consuming an enrollment token.
// Authorization and UUID validation belong at the authenticated API boundary.
func (s SQLStore) ValidatedClaim(ctx context.Context, token, projectID, agentID, claimID string, csrDER []byte) error {
 if _,err:=identity.ValidateCSR(csrDER);err!=nil{return err}
 return s.Claim(ctx,token,projectID,agentID,claimID,csrDER)
}
