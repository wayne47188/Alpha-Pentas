package enrollment

import (
 "context"
 "database/sql"
 "errors"
 "testing"
 "time"
)

func TestSQLStoreRejectsMissingDB(t *testing.T) {
 store:=SQLStore{}
 if _,err:=store.IssueToken(context.Background(),"id","project","issuer",time.Minute);err==nil {t.Fatal("expected error for nil DB")}
 if err:=store.ConsumeToken(context.Background(),"token","project");err==nil {t.Fatal("expected error for nil DB")}
}

func TestSQLStoreRejectsEmptyInputs(t *testing.T) {
 // Empty params are rejected before a query can run.
 store:=SQLStore{DB:&sql.DB{}}
 if _,err:=store.IssueToken(context.Background(),"","project","issuer",time.Minute);err==nil {t.Fatal("expected invalid input")}
 if err:=store.ConsumeToken(context.Background(),"","project");!errors.Is(err,ErrInvalid){t.Fatalf("unexpected error: %v",err)}
}
