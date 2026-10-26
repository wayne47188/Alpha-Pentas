package main

import (
 "flag"
 "fmt"
 "io"
 "net/http"
 "os"
 "time"
)

func main(){
 base:=flag.String("manager","http://127.0.0.1:8080","manager base URL (local development only)")
 flag.Parse()
 client:=http.Client{Timeout:5*time.Second}
 resp,err:=client.Get(*base+"/healthz")
 if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK {fmt.Fprintln(os.Stderr,resp.Status);os.Exit(1)}
 _,_=io.Copy(os.Stdout,resp.Body)
}
