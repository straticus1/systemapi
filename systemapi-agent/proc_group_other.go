//go:build !(linux || darwin)

package main

import (
	"errors"
	"time"
)

// Without process groups only the direct child is killed when the job
// context ends.
type procGroup struct {
	done    chan struct{}
	stopped chan struct{}
}

func (c *jobCmd) Start() error {
	if c.grp != nil {
		return errors.New("jobCommand: already started")
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	if c.WaitDelay == 0 {
		c.WaitDelay = 2 * time.Second
	}
	if err := c.Cmd.Start(); err != nil {
		return err
	}
	g := &procGroup{done: make(chan struct{}), stopped: make(chan struct{})}
	c.grp = g
	go func() {
		defer close(g.stopped)
		select {
		case <-c.ctx.Done():
			_ = c.Process.Kill()
		case <-g.done:
		}
	}()
	return nil
}

func (c *jobCmd) Wait() error {
	g := c.grp
	if g == nil {
		return errors.New("jobCommand: not started")
	}
	err := c.Cmd.Wait()
	close(g.done)
	<-g.stopped
	return err
}
