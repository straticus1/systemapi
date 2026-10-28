//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"log"

	"golang.org/x/sys/unix"
)

// waitExitNoReap returns once pid has exited, without reaping it: a kqueue
// EVFILT_PROC/NOTE_EXIT event. ESRCH at registration means the process has
// already exited. If kqueue itself fails it returns at once; jobCmd.Wait
// still reaps only after the context watcher is done, so no group signal
// follows the reap, but the TERM grace is lost.
func waitExitNoReap(pid int) {
	kq, err := unix.Kqueue()
	if err != nil {
		log.Printf("job process %d: kqueue: %v", pid, err)
		return
	}
	defer unix.Close(kq)
	change := make([]unix.Kevent_t, 1)
	unix.SetKevent(&change[0], pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ONESHOT)
	change[0].Fflags = unix.NOTE_EXIT
	events := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(kq, change, events, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || n > 0 {
			return
		}
	}
}
