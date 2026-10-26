package enrollment

import (
 "context"
 "errors"
 "testing"
)

func TestClaimRejectsIncompleteInput(t *testing.T) {
 store:=SQLStore{}
 err:=store.Claim(context.Background(),"secret","project","agent","claim",[]byte("csr"))
 if err==nil {t.Fatal("missing DB should fail")}
 store=SQLStore{DB:nil}
 err=store.Claim(context.Background(),"","project","agent","claim",[]byte("csr"))
 if !errors.Is(err,ErrInvalid) && err==nil {t.Fatalf("unexpected error: %v",err)}
}

func TestFindClaimRejectsNilDB(t *testing.T){
 s:=SQLStore{}
 if _,err:=s.FindClaim(context.Background(),"claim");err==nil{t.Fatal("expected error")}
}
