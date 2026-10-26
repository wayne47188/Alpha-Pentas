package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
)

type status struct {
	Component string `json:"component"`
	Phase     string `json:"phase"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func main() {
	version := flag.Bool("version", false, "print P0 version information")
	flag.Parse()
	if !*version {
		fmt.Fprintln(os.Stderr, "P0 agent skeleton: no enrollment, collection, command execution or network connection is implemented")
		return
	}
	_ = json.NewEncoder(os.Stdout).Encode(status{Component: "alpha-pentas-agent", Phase: "P0-skeleton", OS: runtime.GOOS, Arch: runtime.GOARCH})
}
