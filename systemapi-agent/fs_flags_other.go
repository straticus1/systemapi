//go:build !unix

package main

import "os"

// No O_NOFOLLOW or O_NONBLOCK on this OS; callers Lstat and re-check.
const (
	openNoFollow = 0
	openNonBlock = 0
)

// fileOwnerIDs has no uid/gid to report on this OS.
func fileOwnerIDs(fi os.FileInfo) (int, int, bool) { return 0, 0, false }

// fileNlink is 1: hard link counts are not reported through FileInfo here.
func fileNlink(fi os.FileInfo) uint64 { return 1 }
