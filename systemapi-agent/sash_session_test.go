package main

import (
	"runtime"
	"testing"
)

func TestSashLoginPlatform(t *testing.T) {
	if sashLogin("breakglass") {
		t.Fatal("breakglass")
	}
	want := runtime.GOOS == "linux"
	if sashLogin("pty") != want || sashLogin("pty_root") != want {
		t.Fatalf("pty login on %s", runtime.GOOS)
	}
}

// attachSashTestGrant, when set, signs a sash/1 grant onto a harness
// request. The Linux test file sets it. Other platforms leave it nil, so
// those tests keep the passwd shell.
var attachSashTestGrant func(t *testing.T, req *ptyStartRequest)
