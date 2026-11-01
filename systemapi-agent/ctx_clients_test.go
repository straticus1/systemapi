package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// hangingServer answers nothing until the request is cancelled.
func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func expectPrompt(t *testing.T, what string, start time.Time, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error from a hung server", what)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("%s: took %s after the script deadline", what, d)
	}
}

func TestDockerCallsEndWithScriptContext(t *testing.T) {
	srv := hangingServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	dc := &DockerClient{ctx: ctx, client: srv.Client(), baseURL: srv.URL}
	start := time.Now()
	_, err := dc.ListContainers()
	expectPrompt(t, "list", start, err)
	_, err = dc.ListImages()
	expectPrompt(t, "images (doJSON)", start, err)
	_, err = dc.execHTTP(srv.URL+"/exec", nil)
	expectPrompt(t, "exec over http", start, err)

	if (&DockerClient{client: srv.Client(), baseURL: srv.URL}).StartContainer("abc") == nil {
		t.Fatal("a client without a context made a call")
	}
}

func TestDockerExecUnixEndsWithScriptContext(t *testing.T) {
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						_ = c.Close()
						return
					}
				}
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	dc := &DockerClient{ctx: ctx, client: &http.Client{}, socketPath: sock, baseURL: "http://localhost"}
	start := time.Now()
	_, err = dc.execUnix("/v1.41/exec/x/start", []byte(`{}`))
	expectPrompt(t, "exec over the unix socket", start, err)
}

func TestKubeCallsEndWithScriptContext(t *testing.T) {
	srv := hangingServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	kc := &K3sClient{ctx: ctx, client: srv.Client(), serverURL: srv.URL}
	start := time.Now()
	_, err := kc.ListNodes()
	expectPrompt(t, "nodes", start, err)
	_, err = kc.doPatch(srv.URL+"/x", []byte(`{}`))
	expectPrompt(t, "patch", start, err)
	if _, err := (&K3sClient{client: srv.Client(), serverURL: srv.URL}).ListNodes(); err == nil {
		t.Fatal("a client without a context made a call")
	}
}

func TestPortCheckUsesScriptContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	engine := newTestEngine(&Entitlements{})
	engine.ctx = ctx
	// An ended script context refuses before any builtin runs.
	if _, err := engine.Execute(`sys.net.port_check("127.0.0.1", 1)` + "\n"); err == nil {
		t.Fatal("ran after the script context ended")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	engine.ctx = context.Background()
	out, err := engine.Execute("print(sys.net.port_check(\"127.0.0.1\", " + strconv.Itoa(port) + ")[\"open\"])\n")
	if err != nil || out != "True\n" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}
