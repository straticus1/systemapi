//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"io"
	"log"
	"os"
	"sync"
	"syscall"
	"time"
)

// jobPipeDrain is how long Wait lets the pipes drain after the group was
// killed before it closes them (a grandchild in another session may still
// hold one).
const jobPipeDrain = time.Second

// groupKill signals every process in group pgid. Tests replace it.
var groupKill = func(pgid int, sig syscall.Signal) error { return syscall.Kill(-pgid, sig) }

type procGroup struct {
	pgid    int
	exited  chan struct{} // the leader has exited; it is not reaped yet
	reaping chan struct{} // Wait is about to reap; the watcher may stop
	escDone chan struct{} // the context watcher has returned
	copied  chan struct{} // every agent-owned pipe reached EOF
	readers []*os.File
}

// interfaceEqual compares two writers the way os/exec does, without
// panicking on an uncomparable dynamic type.
func interfaceEqual(a, b interface{}) (eq bool) {
	defer func() {
		if recover() != nil {
			eq = false
		}
	}()
	return a == b
}

// Start starts the child as the leader of a new process group and watches
// the job context.
func (c *jobCmd) Start() error {
	if c.grp != nil {
		return errors.New("jobCommand: already started")
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	attrs := c.SysProcAttr
	if attrs == nil {
		attrs = &syscall.SysProcAttr{}
	}
	attrs.Setpgid = true
	attrs.Pgid = 0
	setXferPdeathsig(attrs)
	c.SysProcAttr = attrs
	if c.WaitDelay == 0 {
		// Only a non-file Stdin is still copied by os/exec; this bounds it.
		c.WaitDelay = 2 * time.Second
	}

	g := &procGroup{
		exited:  make(chan struct{}),
		reaping: make(chan struct{}),
		escDone: make(chan struct{}),
		copied:  make(chan struct{}),
	}
	type copyJob struct {
		r *os.File
		w io.Writer
	}
	var copies []copyJob
	var writeEnds []*os.File
	closeAll := func() {
		for _, f := range writeEnds {
			_ = f.Close()
		}
		for _, cj := range copies {
			_ = cj.r.Close()
		}
	}
	pipeFor := func(w io.Writer) (*os.File, error) {
		pr, pw, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		copies = append(copies, copyJob{r: pr, w: w})
		writeEnds = append(writeEnds, pw)
		return pw, nil
	}
	if _, isFile := c.Stdout.(*os.File); c.Stdout != nil && !isFile {
		w := c.Stdout
		pw, err := pipeFor(w)
		if err != nil {
			closeAll()
			return err
		}
		c.Stdout = pw
		if interfaceEqual(c.Stderr, w) {
			c.Stderr = pw
		}
	}
	if _, isFile := c.Stderr.(*os.File); c.Stderr != nil && !isFile {
		pw, err := pipeFor(c.Stderr)
		if err != nil {
			closeAll()
			return err
		}
		c.Stderr = pw
	}
	if err := c.Cmd.Start(); err != nil {
		closeAll()
		return err
	}
	for _, f := range writeEnds {
		_ = f.Close()
	}
	g.pgid = c.Process.Pid
	c.grp = g

	var wg sync.WaitGroup
	for _, cj := range copies {
		g.readers = append(g.readers, cj.r)
		wg.Add(1)
		go func(cj copyJob) {
			defer wg.Done()
			_, _ = io.Copy(cj.w, cj.r)
			_ = cj.r.Close()
		}(cj)
	}
	go func() {
		wg.Wait()
		close(g.copied)
	}()
	go func() {
		waitExitNoReap(g.pgid)
		close(g.exited)
	}()
	go func() {
		defer close(g.escDone)
		select {
		case <-c.ctx.Done():
			g.escalate()
		case <-g.reaping:
		}
	}()
	return nil
}

// escalate sends SIGTERM to the group, waits for the leader or the grace,
// then sends SIGKILL. It runs only while the leader is unreaped.
func (g *procGroup) escalate() {
	if err := groupKill(g.pgid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		log.Printf("job process group %d: SIGTERM: %v", g.pgid, err)
	}
	t := time.NewTimer(jobKillGrace)
	defer t.Stop()
	select {
	case <-g.exited:
	case <-t.C:
	}
	if err := groupKill(g.pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		log.Printf("job process group %d: SIGKILL: %v", g.pgid, err)
	}
}

// Wait waits for the leader to exit and for the agent-owned pipes to drain
// (or the context to end and the group to be killed), stops the watcher,
// and only then reaps the leader.
func (c *jobCmd) Wait() error {
	g := c.grp
	if g == nil {
		return errors.New("jobCommand: not started")
	}
	select {
	case <-g.exited:
	case <-c.ctx.Done():
		<-g.escDone
		<-g.exited
	}
	select {
	case <-g.copied:
	case <-c.ctx.Done():
		<-g.escDone
		t := time.NewTimer(jobPipeDrain)
		select {
		case <-g.copied:
		case <-t.C:
			for _, r := range g.readers {
				_ = r.Close()
			}
			<-g.copied
		}
		t.Stop()
	}
	close(g.reaping)
	<-g.escDone
	return c.Cmd.Wait()
}
