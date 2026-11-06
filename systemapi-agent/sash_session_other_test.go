//go:build !linux

package main

import "testing"

func TestPrepareSashOtherIsMissing(t *testing.T) {
	_, _, extra, stop, err := prepareSash([]byte("not-empty"), "fleet", "emer", sashBind{}, sashTargets{}, nil, nil)
	if sashStatusCode(err) != "sash_missing" {
		t.Fatalf("err %v", err)
	}
	if extra != nil || stop != nil {
		t.Fatal("fds")
	}
}
