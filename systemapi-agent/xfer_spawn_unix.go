//go:build unix

// Starting a sahxfer recv child (sahxfer end-to-end plan, decision 3 and
// item 17). Threats: the transfer running with the agent's privileges (the
// child gets SysProcAttr.Credential with the identity's uid, gid and groups,
// the same path as startFileHelperProc; only xfer_root on a root agent runs
// as root), the agent's secrets reaching the child (empty environment, Dir
// "/", and only the fds the caller sets in ExtraFiles), and a child that
// outlives a crashed agent (Pdeathsig SIGTERM on Linux, so recv can still
// delete its temp file; fd 3 EOF everywhere). Does NOT confine recv beyond
// the kernel's permissions for its identity.
package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func startXferProc(id *ptyIdentity, exe string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(exe, args...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	attrs := &syscall.SysProcAttr{Setsid: true}
	setXferPdeathsig(attrs)
	if id.drop {
		attrs.Credential = &syscall.Credential{Uid: id.uid, Gid: id.gid, Groups: id.groups}
	}
	cmd.SysProcAttr = attrs
	return cmd, nil
}

func checkXferBinOwner(fi os.FileInfo, agentUID int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("--xfer-bin owner unknown")
	}
	if st.Uid != 0 && int64(st.Uid) != int64(agentUID) {
		return errors.New("not owned by root or the agent user")
	}
	return nil
}
