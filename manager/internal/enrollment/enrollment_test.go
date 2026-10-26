package enrollment

import (
 "errors"
 "sync"
 "sync/atomic"
 "testing"
 "time"
)

func TestTokenSingleUse(t *testing.T){
 s:=NewStore()
 tok,err:=s.Issue("project-a",30*time.Minute)
 if err!=nil {t.Fatal(err)}
 if err:=s.Consume(tok,"project-b");!errors.Is(err,ErrProject){t.Fatalf("wrong project: %v",err)}
 if err:=s.Consume(tok,"project-a");err!=nil {t.Fatal(err)}
 if err:=s.Consume(tok,"project-a");!errors.Is(err,ErrInvalid){t.Fatalf("reused: %v",err)}
}

func TestConcurrentConsume(t *testing.T){
 s:=NewStore()
 tok,_:=s.Issue("p",time.Minute)
 var successes atomic.Int32
 var wg sync.WaitGroup
 for i:=0;i<32;i++{
  wg.Add(1)
  go func(){defer wg.Done();if s.Consume(tok,"p")==nil{successes.Add(1)}}()
 }
 wg.Wait()
 if got:=successes.Load();got!=1{t.Fatalf("successes=%d",got)}
}

func TestExpired(t *testing.T){
 s:=NewStore()
 now:=time.Now()
 s.now=func()time.Time{return now}
 tok,_:=s.Issue("p",time.Minute)
 now=now.Add(61*time.Second)
 if err:=s.Consume(tok,"p");!errors.Is(err,ErrInvalid){t.Fatalf("expired accepted: %v",err)}
}
