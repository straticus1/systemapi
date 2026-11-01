//go:build darwin

package main

import (
	"errors"
	"log"
	"time"

	"golang.org/x/sys/unix"
)

// waitExitNoReap returns once pid has exited, without reaping it. It waits
// for a kqueue EVFILT_PROC/NOTE_EXIT event (or ESRCH when the event is
// registered after the exit). If kqueue fails for any other reason it polls
// getpgid(pid) every 100 ms instead: on darwin that answers ESRCH for a
// zombie and succeeds for a live process. Either way it never returns
// before the exit, so the context-driven escalation always runs before
// jobCmd.Wait reaps the leader.
func waitExitNoReap(pid int) {
	err := kqueueExitWait(pid)
	if err == nil {
		return
	}
	log.Printf("job process %d: kqueue: %v; polling for its exit", pid, err)
	for {
		if _, err := unix.Getpgid(pid); errors.Is(err, unix.ESRCH) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// kqueueExitWait blocks until pid's NOTE_EXIT event fires, or the
// registration reports ESRCH because pid already exited; both return nil.
// Any other failure is returned.
func kqueueExitWait(pid int) error {
	kq, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(kq)
	change := make([]unix.Kevent_t, 1)
	unix.SetKevent(&change[0], pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ONESHOT)
	change[0].Fflags = unix.NOTE_EXIT
	events := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(kq, change, events, nil)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ESRCH):
			return nil
		case err != nil:
			return err
		}
		if n == 0 {
			continue
		}
		ev := events[0]
		if ev.Flags&unix.EV_ERROR != 0 {
			if unix.Errno(ev.Data) == unix.ESRCH {
				return nil
			}
			return unix.Errno(ev.Data)
		}
		if ev.Fflags&unix.NOTE_EXIT != 0 {
			return nil
		}
	}
}
