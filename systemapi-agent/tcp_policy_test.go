package main

import (
	"net/netip"
	"testing"
)

func TestTCPAllowParse(t *testing.T) {
	rules, err := parseTCPAllow("local:5432,10.0.0.0/24:3389,10.0.0.0/24:8000-8099,[2001:db8::/32]:22,10.1.2.3:443,fd00::1:80")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 6 || !rules[0].local || rules[0].lo != 5432 || rules[2].lo != 8000 || rules[2].hi != 8099 {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[4].prefix.Bits() != 32 || rules[5].prefix.Bits() != 128 {
		t.Fatalf("bare addresses are single hosts: %+v", rules[4:])
	}
	for _, empty := range []string{"", "  "} {
		r, err := parseTCPAllow(empty)
		if err != nil || len(r) != 0 {
			t.Fatalf("%q: deny-all expected, got %v %v", empty, r, err)
		}
	}
	for _, bad := range []string{
		"local", "local:", "local:0", "local:65536", "local:22-21", "local:022", "local:a", ":22",
		"db.internal:22", "10.0.0.0/33:22", "10.0.0.0/24", "fe80::1%eth0:22", "[2001:db8::1:22", "::ffff:10.0.0.1:22",
		"local:5432,", "local:1-2-3",
	} {
		if _, err := parseTCPAllow(bad); err == nil {
			t.Fatalf("%q should be refused", bad)
		}
	}
}

func TestTCPAllowMatchesExactAddress(t *testing.T) {
	rules, err := parseTCPAllow("local:5432,10.0.0.0/24:3389,10.0.0.0/24:8000-8099,2001:db8::/32:22")
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr
	cases := []struct {
		addr  netip.Addr
		local bool
		port  int
		want  bool
	}{
		{ip("127.0.0.1"), true, 5432, true},
		{ip("127.0.0.1"), true, 5433, false},
		{ip("10.0.0.7"), false, 3389, true},
		{ip("10.0.0.7"), false, 8050, true},
		{ip("10.0.0.7"), false, 8100, false},
		{ip("10.0.1.7"), false, 3389, false},
		{ip("2001:db8::7"), false, 22, true},
		{ip("2001:db9::7"), false, 22, false},
		// A CIDR entry never matches "local", and "local" never an address.
		{ip("127.0.0.1"), false, 5432, false},
	}
	for _, c := range cases {
		if got := tcpAllowed(rules, c.addr, c.local, c.port); got != c.want {
			t.Fatalf("%v local=%v :%d = %v, want %v", c.addr, c.local, c.port, got, c.want)
		}
	}
	// TCP §14: an empty agent allowlist refuses everything.
	if tcpAllowed(nil, ip("127.0.0.1"), true, 5432) || tcpAllowed(nil, ip("10.0.0.7"), false, 3389) {
		t.Fatal("empty allowlist must deny")
	}
}

func TestTCPTargetRefusedClasses(t *testing.T) {
	for _, host := range []string{
		"169.254.169.254", "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1",
		"100.100.100.200", "::", "fe80::1", "ff02::1", "fd00:ec2::254",
		// Loopback by any spelling but "local".
		"127.0.0.1", "127.9.9.9", "::1",
		// Non-canonical spellings and names are refused, never resolved.
		"::ffff:10.0.0.7", "2001:DB8::1", "2001:db8:0:0:0:0:0:1", "010.0.0.7", "db.internal", "localhost", "fe80::1%eth0",
	} {
		if _, _, code := tcpTargetAddr(host); code != "target_forbidden" {
			t.Fatalf("%s: code %q, want target_forbidden", host, code)
		}
	}
	for _, host := range []string{"10.0.0.7", "2001:db8::1", "100.100.100.201", "169.255.0.1", "fd00:ec2::253"} {
		a, local, code := tcpTargetAddr(host)
		if code != "" || local || a.String() != host {
			t.Fatalf("%s: %v %v %q", host, a, local, code)
		}
	}
	a, local, code := tcpTargetAddr("local")
	if code != "" || !local || a.String() != "127.0.0.1" {
		t.Fatalf("local: %v %v %q", a, local, code)
	}
}
