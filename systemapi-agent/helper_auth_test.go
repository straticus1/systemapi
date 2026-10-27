package main

// Negative tests for the helpers' own lease authorization (helper_auth.go).
//
// Threats exercised: a compromised agent writing a request file. The helper
// must refuse unless the request carries a lease signed by the control-plane
// key it loads itself from a root-owned trust file, for this host, unexpired,
// whose payload binds exactly the requested action, target and content, and
// whose nonce has not been consumed before (also by an earlier helper
// process). It must also refuse a trust file that is a symlink, group/other
// writable, owned by someone else, or sitting in a writable directory. Every
// refusal is a recorded result and the write seam is never reached.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// withHelperTrust writes a trust file for pub/host into a fresh 0755 dir,
// points the helper at it (owner = the test user, since tests do not run as
// root) and gives it a fresh replay store. Returns the trust file path.
func withHelperTrust(t *testing.T, pub ed25519.PublicKey, host string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc-systemapi-agent")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "helper-trust.json")
	b, err := json.Marshal(map[string]string{"host_id": host, "control_pubkey": base64.StdEncoding.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	prevPath, prevUID, prevReplay := helperTrustPath, helperTrustOwnerUID, helperReplayDir
	helperTrustPath = path
	helperTrustOwnerUID = uint32(os.Getuid())
	helperReplayDir = filepath.Join(t.TempDir(), "sah-helper", "consumed")
	t.Cleanup(func() {
		helperTrustPath, helperTrustOwnerUID, helperReplayDir = prevPath, prevUID, prevReplay
	})
	return path
}

// newHelperSigner makes a control key, trusts it for ptyTestHost, and returns
// the private half.
func newHelperSigner(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	withHelperTrust(t, pub, ptyTestHost)
	return priv
}

// configWriteLease signs a sys_config write lease for target/content.
func configWriteLease(t *testing.T, priv ed25519.PrivateKey, target, content string, exp int64) *Lease {
	t.Helper()
	payload, err := sysConfigLeasePayload("write", target, sysSHA256Hex(content))
	if err != nil {
		t.Fatal(err)
	}
	return signLease(t, priv, ptyTestHost, "sys_config", payload, exp)
}

// runConfigReq writes one request file, runs the helper and returns its result.
func runConfigReq(t *testing.T, dir string, req configHelperReq) configHelperRes {
	t.Helper()
	_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	writeConfigReqFile(t, dir, testHelperID, req)
	if code := runConfigHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0 (result recorded)", code)
	}
	return readConfigResFile(t, dir, testHelperID)
}

func TestHelperAuthAcceptsValidLease(t *testing.T) {
	priv := newHelperSigner(t)
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	l := configWriteLease(t, priv, "/etc/nginx/nginx.conf", "server {}\n", inFuture(time.Minute))
	res := runConfigReq(t, dir, configHelperReq{Target: "/etc/nginx/nginx.conf", Content: "server {}\n", Lease: l})
	if !res.OK {
		t.Fatalf("result=%+v, want ok", res)
	}
	if len(*calls) != 1 {
		t.Fatalf("write calls=%v", *calls)
	}
}

func TestHelperAuthRefuses(t *testing.T) {
	const target, content = "/etc/nginx/nginx.conf", "server {}\n"
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		req  func(t *testing.T, priv ed25519.PrivateKey) configHelperReq
		want string
	}{
		{"missing lease", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			return configHelperReq{Target: target, Content: content}
		}, "lease_missing"},
		{"forged signature", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			l := configWriteLease(t, priv, target, content, inFuture(time.Minute))
			sig, _ := base64.StdEncoding.DecodeString(l.Signature)
			sig[0] ^= 0xff
			l.Signature = base64.StdEncoding.EncodeToString(sig)
			return configHelperReq{Target: target, Content: content, Lease: l}
		}, "lease_bad_signature"},
		{"wrong key", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			return configHelperReq{Target: target, Content: content, Lease: configWriteLease(t, otherPriv, target, content, inFuture(time.Minute))}
		}, "lease_bad_signature"},
		{"expired", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			return configHelperReq{Target: target, Content: content, Lease: configWriteLease(t, priv, target, content, time.Now().Add(-10*time.Minute).Unix())}
		}, "lease_expired"},
		{"too far in the future", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			return configHelperReq{Target: target, Content: content, Lease: configWriteLease(t, priv, target, content, time.Now().Add(time.Hour).Unix())}
		}, "lease_expiry_too_far"},
		{"target mismatch", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			return configHelperReq{Target: "/etc/sudoers", Content: content, Lease: configWriteLease(t, priv, target, content, inFuture(time.Minute))}
		}, "lease_payload_mismatch"},
		{"sibling target", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			return configHelperReq{Target: target + "-evil", Content: content, Lease: configWriteLease(t, priv, target, content, inFuture(time.Minute))}
		}, "lease_payload_mismatch"},
		{"content mismatch", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			return configHelperReq{Target: target, Content: "evil\n", Lease: configWriteLease(t, priv, target, content, inFuture(time.Minute))}
		}, "lease_payload_mismatch"},
		{"read lease used for write", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			p, _ := sysConfigLeasePayload("read", target, "")
			return configHelperReq{Target: target, Content: content, Lease: signLease(t, priv, ptyTestHost, "sys_config", p, inFuture(time.Minute))}
		}, "lease_payload_mismatch"},
		{"other action", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			p, _ := sysConfigLeasePayload("write", target, sysSHA256Hex(content))
			return configHelperReq{Target: target, Content: content, Lease: signLease(t, priv, ptyTestHost, "sys_tweak", p, inFuture(time.Minute))}
		}, "lease_bad_action"},
		{"other host", func(t *testing.T, priv ed25519.PrivateKey) configHelperReq {
			p, _ := sysConfigLeasePayload("write", target, sysSHA256Hex(content))
			return configHelperReq{Target: target, Content: content, Lease: signLease(t, priv, "44444444-4444-4444-8444-444444444444", "sys_config", p, inFuture(time.Minute))}
		}, "lease_bad_host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv := newHelperSigner(t)
			dir := withConfigHelperStateDir(t)
			calls := withFakeConfigWrite(t, nil)
			res := runConfigReq(t, dir, tc.req(t, priv))
			if res.OK || res.Error != tc.want {
				t.Fatalf("result=%+v, want %s", res, tc.want)
			}
			if len(*calls) != 0 {
				t.Fatalf("write must not run: %v", *calls)
			}
		})
	}
}

func TestHelperAuthRefusesReplay(t *testing.T) {
	priv := newHelperSigner(t)
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	l := configWriteLease(t, priv, "/etc/nginx/nginx.conf", "a\n", inFuture(time.Minute))
	req := configHelperReq{Target: "/etc/nginx/nginx.conf", Content: "a\n", Lease: l}
	if res := runConfigReq(t, dir, req); !res.OK {
		t.Fatalf("first use: %+v", res)
	}
	if res := runConfigReq(t, dir, req); res.OK || res.Error != "replay" {
		t.Fatalf("second use: %+v, want replay", res)
	}
	if len(*calls) != 1 {
		t.Fatalf("write calls=%v, want exactly one", *calls)
	}
}

// TestHelperAuthRefusesReplayAcrossRestart consumes a lease in this process,
// then runs the helper in a FRESH process (the test binary re-executed) with
// the same trust file and replay store. The second process has no memory of
// the first; only the durable store can refuse it.
func TestHelperAuthRefusesReplayAcrossRestart(t *testing.T) {
	priv := newHelperSigner(t)
	dir := withConfigHelperStateDir(t)
	withFakeConfigWrite(t, nil)
	l := configWriteLease(t, priv, "/etc/nginx/nginx.conf", "a\n", inFuture(time.Minute))
	req := configHelperReq{Target: "/etc/nginx/nginx.conf", Content: "a\n", Lease: l}
	if res := runConfigReq(t, dir, req); !res.OK {
		t.Fatalf("first use: %+v", res)
	}
	_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	writeConfigReqFile(t, dir, testHelperID, req)

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperAuthSubprocess$")
	cmd.Env = append(os.Environ(),
		"SAH_HELPER_SUBPROC=1",
		"SAH_HELPER_STATE="+dir,
		"SAH_HELPER_TRUST="+helperTrustPath,
		"SAH_HELPER_REPLAY="+helperReplayDir,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
	res := readConfigResFile(t, dir, testHelperID)
	if res.OK || res.Error != "replay" {
		t.Fatalf("fresh process: %+v, want replay", res)
	}
}

// TestHelperAuthSubprocess is the fresh helper process for the restart test.
// It only runs when re-executed by that test.
func TestHelperAuthSubprocess(t *testing.T) {
	if os.Getenv("SAH_HELPER_SUBPROC") != "1" {
		t.Skip("subprocess entry point")
	}
	configHelperStateDir = os.Getenv("SAH_HELPER_STATE")
	helperTrustPath = os.Getenv("SAH_HELPER_TRUST")
	helperReplayDir = os.Getenv("SAH_HELPER_REPLAY")
	helperTrustOwnerUID = uint32(os.Getuid())
	configHelperWrite = func(path, content string) error {
		t.Errorf("write reached in the subprocess for %s", path)
		return nil
	}
	if code := runConfigHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
}

func TestHelperAuthPrunesExpiredReplayEntries(t *testing.T) {
	newHelperSigner(t)
	now := time.Now()
	old := "0123456789abcdef0123456789abcdef"
	if err := consumeHelperNonce(old, now.Add(-time.Hour).Unix(), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A fresh consume prunes the long-expired entry.
	if err := consumeHelperNonce("fedcba9876543210fedcba9876543210", now.Add(time.Minute).Unix(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(helperReplayDir, old)); !os.IsNotExist(err) {
		t.Fatalf("expired entry not pruned: %v", err)
	}
}

func TestHelperAuthReplayStoreIsBounded(t *testing.T) {
	newHelperSigner(t)
	prevMax := helperReplayMax
	helperReplayMax = 8
	t.Cleanup(func() { helperReplayMax = prevMax })
	now := time.Now()
	if err := os.MkdirAll(helperReplayDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < helperReplayMax; i++ {
		n := make([]byte, 16)
		if _, err := rand.Read(n); err != nil {
			t.Fatal(err)
		}
		if err := consumeHelperNonce(hex.EncodeToString(n), now.Add(time.Minute).Unix(), now); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if err := consumeHelperNonce("fedcba9876543210fedcba9876543210", now.Add(time.Minute).Unix(), now); err == nil {
		t.Fatal("a full replay store must refuse (fail closed)")
	}
}

func TestHelperAuthRefusesUntrustedKeyFile(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, path string)
	}{
		{"missing", func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string) {
			real := filepath.Join(t.TempDir(), "real.json")
			b, _ := os.ReadFile(path)
			if err := os.WriteFile(real, b, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"world writable", func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o666); err != nil {
				t.Fatal(err)
			}
		}},
		{"group writable", func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o664); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable directory", func(t *testing.T, path string) {
			if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlinked directory", func(t *testing.T, path string) {
			link := filepath.Join(t.TempDir(), "linkdir")
			if err := os.Symlink(filepath.Dir(path), link); err != nil {
				t.Fatal(err)
			}
			helperTrustPath = filepath.Join(link, filepath.Base(path))
		}},
		{"wrong owner", func(t *testing.T, path string) {
			helperTrustOwnerUID = uint32(os.Getuid()) + 1
		}},
		{"bad key", func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(`{"host_id":"`+ptyTestHost+`","control_pubkey":"AAAA"}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, path string) {
			big := make([]byte, helperTrustMax+1)
			for i := range big {
				big[i] = ' '
			}
			if err := os.WriteFile(path, big, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			path := withHelperTrust(t, pub, ptyTestHost)
			dir := withConfigHelperStateDir(t)
			calls := withFakeConfigWrite(t, nil)
			tc.setup(t, path)
			l := configWriteLease(t, priv, "/etc/nginx/nginx.conf", "a\n", inFuture(time.Minute))
			res := runConfigReq(t, dir, configHelperReq{Target: "/etc/nginx/nginx.conf", Content: "a\n", Lease: l})
			if res.OK || res.Error != "trust_unavailable" {
				t.Fatalf("result=%+v, want trust_unavailable", res)
			}
			if len(*calls) != 0 {
				t.Fatalf("write must not run: %v", *calls)
			}
		})
	}
}

func TestSysctlHelperRequiresMatchingLease(t *testing.T) {
	priv := newHelperSigner(t)
	dir := withHelperStateDir(t)
	calls := withFakeWrite(t, nil)
	p, _ := sysTweakLeasePayload("sysctl-set", "net.ipv4.ip_forward", "0", "", "", "", "")
	cases := []struct {
		name string
		req  sysctlHelperReq
		want string
	}{
		{"missing lease", sysctlHelperReq{Key: "net.ipv4.ip_forward", Value: "1"}, "lease_missing"},
		{"value mismatch", sysctlHelperReq{Key: "net.ipv4.ip_forward", Value: "1", Lease: signLease(t, priv, ptyTestHost, "sys_tweak", p, inFuture(time.Minute))}, "lease_payload_mismatch"},
		{"config lease", sysctlHelperReq{Key: "net.ipv4.ip_forward", Value: "0", Lease: signLease(t, priv, ptyTestHost, "sys_config", p, inFuture(time.Minute))}, "lease_bad_action"},
	}
	for _, tc := range cases {
		_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
		writeReqFile(t, dir, testHelperID, tc.req)
		if code := runSysctlHelper([]string{testHelperID}); code != 0 {
			t.Fatalf("%s: exit=%d", tc.name, code)
		}
		if res := readResFile(t, dir, testHelperID); res.OK || res.Error != tc.want {
			t.Fatalf("%s: result=%+v, want %s", tc.name, res, tc.want)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run: %v", *calls)
	}
}

func TestOverrideHelperRequiresMatchingLease(t *testing.T) {
	priv := newHelperSigner(t)
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	limitP, _ := sysTweakLeasePayload("resource-limit-set", "", "1024", "nginx.service", "LimitNOFILE", "", "")
	unitP, _ := sysTweakLeasePayload("unit-override-set", "", "", "nginx.service", "", "x", sysSHA256Hex("[Service]\nA=1\n"))
	cases := []struct {
		name string
		req  overrideHelperReq
		want string
	}{
		{"missing lease", overrideHelperReq{Kind: overrideKindLimit, Unit: "nginx.service", Limit: "LimitNOFILE", Value: "1024"}, "lease_missing"},
		{"limit value mismatch", overrideHelperReq{Kind: overrideKindLimit, Unit: "nginx.service", Limit: "LimitNOFILE", Value: "65536",
			Lease: signLease(t, priv, ptyTestHost, "sys_tweak", limitP, inFuture(time.Minute))}, "lease_payload_mismatch"},
		{"limit unit mismatch", overrideHelperReq{Kind: overrideKindLimit, Unit: "sshd.service", Limit: "LimitNOFILE", Value: "1024",
			Lease: signLease(t, priv, ptyTestHost, "sys_tweak", limitP, inFuture(time.Minute))}, "lease_payload_mismatch"},
		{"override body mismatch", overrideHelperReq{Kind: overrideKindUnit, Unit: "nginx.service", Name: "x", Content: "[Service]\nExecStart=/bin/evil\n",
			Lease: signLease(t, priv, ptyTestHost, "sys_tweak", unitP, inFuture(time.Minute))}, "lease_payload_mismatch"},
		{"limit lease as override", overrideHelperReq{Kind: overrideKindUnit, Unit: "nginx.service", Name: "x", Content: "[Service]\nA=1\n",
			Lease: signLease(t, priv, ptyTestHost, "sys_tweak", limitP, inFuture(time.Minute))}, "lease_payload_mismatch"},
	}
	for _, tc := range cases {
		_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
		writeOverrideReqFile(t, dir, testHelperID, tc.req)
		if code := runOverrideHelper([]string{testHelperID}); code != 0 {
			t.Fatalf("%s: exit=%d", tc.name, code)
		}
		if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != tc.want {
			t.Fatalf("%s: result=%+v, want %s", tc.name, res, tc.want)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run: %v", *calls)
	}
}

// The last moment a lease verifies is expiry+leaseSkew. A helper that verified
// it then must still find its nonce recorded even if another helper, running a
// little later, pruned the store in between: an entry is kept until well past
// the acceptance window, so the same lease cannot be consumed twice.
func TestHelperAuthPruneKeepsEntriesThatCanStillVerify(t *testing.T) {
	newHelperSigner(t)
	exp := time.Now().Unix()
	edge := time.Unix(exp, 0).Add(leaseSkew) // the last second verifyLease accepts
	nonce := "0123456789abcdef0123456789abcdef"
	if err := consumeHelperNonce(nonce, exp, edge); err != nil {
		t.Fatal(err)
	}
	// Another helper, a little later, consumes an unrelated nonce and prunes.
	if err := consumeHelperNonce("fedcba9876543210fedcba9876543210", exp+300, edge.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	// A second helper that verified the same lease at the edge must be refused.
	if err := consumeHelperNonce(nonce, exp, edge); !errors.Is(err, errReplay) {
		t.Fatalf("lease consumed twice across a prune: %v", err)
	}
}

// Parallel helpers consuming the same nonce at the expiry edge, interleaved
// with helpers that prune: exactly one consume of that nonce succeeds.
func TestHelperAuthConcurrentConsumeNearExpiry(t *testing.T) {
	newHelperSigner(t)
	exp := time.Now().Unix()
	edge := time.Unix(exp, 0).Add(leaseSkew)
	nonce := "00112233445566778899aabbccddeeff"
	const n = 16
	var wg sync.WaitGroup
	var ok atomic.Int32
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			err := consumeHelperNonce(nonce, exp, edge)
			if err == nil {
				ok.Add(1)
			} else if !errors.Is(err, errReplay) {
				errs <- err
			}
		}()
		go func(i int) {
			defer wg.Done()
			other := fmt.Sprintf("%032x", i+1)
			if err := consumeHelperNonce(other, exp+300, edge.Add(time.Duration(i+1)*time.Second)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("unexpected store error: %v", err)
	}
	if got := ok.Load(); got != 1 {
		t.Fatalf("same nonce consumed %d times, want exactly 1", got)
	}
}

// The lock file lives in the store but is not a nonce: it must not count
// toward helperReplayMax nor be pruned.
func TestHelperAuthReplayLockNotCounted(t *testing.T) {
	newHelperSigner(t)
	prevMax := helperReplayMax
	helperReplayMax = 1
	t.Cleanup(func() { helperReplayMax = prevMax })
	now := time.Now()
	if err := consumeHelperNonce("0123456789abcdef0123456789abcdef", now.Add(time.Minute).Unix(), now); err != nil {
		t.Fatalf("first entry refused (lock file counted?): %v", err)
	}
	info, err := os.Lstat(filepath.Join(helperReplayDir, helperReplayLockName))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("lock file missing or not regular: %v", err)
	}
}

// A symlink planted at the lock path is refused, not followed.
func TestHelperAuthReplayLockRefusesSymlink(t *testing.T) {
	newHelperSigner(t)
	if err := os.MkdirAll(helperReplayDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, filepath.Join(helperReplayDir, helperReplayLockName)); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := consumeHelperNonce("0123456789abcdef0123456789abcdef", now.Add(time.Minute).Unix(), now); err == nil {
		t.Fatal("a symlinked lock file must be refused")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("lock symlink was followed: %v", err)
	}
}

// The exclusive flock must be held while an expired entry is pruned and while
// the new nonce is recorded: O_EXCL alone does not serialise check+prune+
// record across helper processes (the count against helperReplayMax and a
// prune racing a consume both depend on it). The hook takes a second open
// file description of the lock and tries a non-blocking exclusive lock, which
// must fail while the consume holds it.
func TestHelperAuthReplayLockHeldDuringPruneAndRecord(t *testing.T) {
	newHelperSigner(t)
	now := time.Now()
	old := "0123456789abcdef0123456789abcdef"
	if err := consumeHelperNonce(old, now.Add(-time.Hour).Unix(), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	prev := helperReplayHook
	helperReplayHook = func(stage string) {
		seen[stage] = true
		f, err := os.OpenFile(filepath.Join(helperReplayDir, helperReplayLockName), os.O_RDWR, 0)
		if err != nil {
			t.Errorf("%s: open lock: %v", stage, err)
			return
		}
		defer f.Close()
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			t.Errorf("%s: replay lock is not held", stage)
			return
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Errorf("%s: flock: %v", stage, err)
		}
	}
	t.Cleanup(func() { helperReplayHook = prev })
	if err := consumeHelperNonce("fedcba9876543210fedcba9876543210", now.Add(time.Minute).Unix(), now); err != nil {
		t.Fatal(err)
	}
	if !seen["prune"] || !seen["record"] {
		t.Fatalf("hook stages seen: %v, want prune and record", seen)
	}
}
