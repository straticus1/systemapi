//go:build linux

package main

import (
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Threats: a Linux login that falls open to bash, a grant checked after
// pipes are open, a verb socket inherited by a later child, and a log line
// that contains grant or key bytes. pty and pty_root exec sash --session
// only after the grant verifies. A missing binary is sash_missing. A bad
// grant does not exec. Does NOT hold the grant private key. Does NOT import
// sash. Does NOT fall open to bash.

var sashLookPath = exec.LookPath

func sashLogin(action string) bool {
	return action == "pty" || action == "pty_root"
}

func sashPipeGone(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}

func sashWriteAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func sashClosePipe(f *os.File) {
	if f == nil {
		return
	}
	if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		log.Printf("sash session pipe close failed")
	}
}

func prepareSash(grant []byte, fleetPath, emerPath string, b sashBind, targets sashTargets, leaseFn func() time.Time, id *ptyIdentity) (string, []string, []*os.File, func(), error) {
	if len(grant) == 0 {
		return "", nil, nil, nil, errSashGrantMissing
	}
	bin, err := sashLookPath("sash")
	if err != nil {
		return "", nil, nil, nil, errSashMissing
	}
	fleetPub, err := readSashPub(fleetPath)
	if err != nil {
		return "", nil, nil, nil, err
	}
	emerPub, err := readSashPub(emerPath)
	if err != nil {
		return "", nil, nil, nil, err
	}
	verified, err := bindSashGrant(grant, fleetPub, emerPub, b)
	if err != nil {
		return "", nil, nil, nil, err
	}
	grantCopy := append([]byte(nil), grant...)
	fleetCopy := append([]byte(nil), fleetPub...)
	emerCopy := append([]byte(nil), emerPub...)
	targetsCopy := copySashTargets(targets)

	var opened []*os.File
	closeOpened := func() {
		for _, f := range opened {
			sashClosePipe(f)
		}
	}
	mkPipe := func() (r, w *os.File, err error) {
		r, w, err = os.Pipe()
		if err != nil {
			return nil, nil, err
		}
		opened = append(opened, r, w)
		return r, w, nil
	}
	grantR, grantW, err := mkPipe()
	if err != nil {
		closeOpened()
		return "", nil, nil, nil, err
	}
	fleetR, fleetW, err := mkPipe()
	if err != nil {
		closeOpened()
		return "", nil, nil, nil, err
	}
	emerR, emerW, err := mkPipe()
	if err != nil {
		closeOpened()
		return "", nil, nil, nil, err
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		closeOpened()
		return "", nil, nil, nil, err
	}
	syscall.CloseOnExec(fds[0])
	syscall.CloseOnExec(fds[1])
	parent := os.NewFile(uintptr(fds[0]), "sash-verb")
	child := os.NewFile(uintptr(fds[1]), "sash-verb-child")
	opened = append(opened, parent, child)

	go func() {
		writeOne := func(f *os.File, body []byte) {
			werr := sashWriteAll(f, body)
			sashClosePipe(f)
			if werr != nil && !sashPipeGone(werr) {
				log.Printf("sash session pipe write failed")
			}
		}
		writeOne(grantW, grantCopy)
		writeOne(fleetW, fleetCopy)
		writeOne(emerW, emerCopy)
	}()
	go func() {
		serr := sashServe(parent, func(call sashCall) (sashResult, error) {
			return sashDispatch(verified, targetsCopy, leaseFn, id, call)
		})
		if serr != nil && !errors.Is(serr, io.EOF) && !sashPipeGone(serr) {
			log.Printf("sash verb serve ended")
		}
	}()

	var once sync.Once
	stop := func() {
		once.Do(func() {
			if cerr := parent.Close(); cerr != nil && !errors.Is(cerr, os.ErrClosed) {
				log.Printf("sash verb socket close failed")
			}
		})
	}
	extra := []*os.File{grantR, fleetR, emerR, child}
	return bin, []string{"--session"}, extra, stop, nil
}
