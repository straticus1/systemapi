// TCP-forward target policy on the agent (docs/sah-tcp-protocol.md §4).
// Threats: the agent used as an SSRF pivot by a compromised or buggy control
// plane. The agent keeps its own key, independent of the server policy: the
// --tcp-allow list (deny by default, empty refuses everything) is checked
// against the exact address the agent will dial, and the always-refused
// classes (unspecified, link-local, multicast, broadcast, 240/4, cloud
// metadata 100.100.100.200, fd00:ec2::254 and the Azure WireServer
// 168.63.129.16, the IPv4-embedding IPv6 ranges ::/96, 64:ff9b::/96,
// 64:ff9b:1::/48 and 2002::/16, loopback by any spelling but "local") are
// refused whatever either policy says. Targets are IP literals
// only: a name is never resolved, so DNS rebinding has nothing to work on.
// The target must be in canonical form (the server normalizes it), so one
// address has one spelling in the lease, the allowlist check and the dial.
// Does NOT see what an allowed target does with the connection (an allowed
// proxy is a pivot by design).
package main

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

// tcpAllowRule is one --tcp-allow entry: "local:<ports>" or
// "<ip|cidr>:<ports>", ports "N" or "N-M". IPv6 may be bracketed.
type tcpAllowRule struct {
	local  bool
	prefix netip.Prefix
	lo, hi int
}

var errBadTCPAllow = errors.New("bad --tcp-allow entry")

var tcpForbiddenPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32", "100.100.100.200/32",
		"168.63.129.16/32", "127.0.0.0/8",
		// ::/96 (IPv4-compatible) covers :: and ::1; NAT64 and 6to4 embed
		// IPv4 and are refused whole. Keep in sync with FORBIDDEN_V4/V6 in
		// controlplane/channels.js.
		"::/96", "fe80::/10", "ff00::/8", "fd00:ec2::254/128", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func parsePortRange(s string) (int, int, error) {
	lo, hi := s, s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		lo, hi = s[:i], s[i+1:]
	}
	a, err1 := strconv.Atoi(lo)
	b, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b || lo != strconv.Itoa(a) || hi != strconv.Itoa(b) {
		return 0, 0, errBadTCPAllow
	}
	return a, b, nil
}

// parseTCPAllow parses the --tcp-allow flag. Empty means deny all.
func parseTCPAllow(flagValue string) ([]tcpAllowRule, error) {
	var out []tcpAllowRule
	if strings.TrimSpace(flagValue) == "" {
		return out, nil
	}
	for _, raw := range strings.Split(flagValue, ",") {
		entry := strings.TrimSpace(raw)
		i := strings.LastIndexByte(entry, ':')
		if i <= 0 {
			return nil, errBadTCPAllow
		}
		addr, ports := entry[:i], entry[i+1:]
		lo, hi, err := parsePortRange(ports)
		if err != nil {
			return nil, err
		}
		if addr == "local" {
			out = append(out, tcpAllowRule{local: true, lo: lo, hi: hi})
			continue
		}
		if strings.HasPrefix(addr, "[") {
			if !strings.HasSuffix(addr, "]") {
				return nil, errBadTCPAllow
			}
			addr = addr[1 : len(addr)-1]
		}
		if strings.ContainsAny(addr, "%[]") {
			return nil, errBadTCPAllow
		}
		var prefix netip.Prefix
		if strings.Contains(addr, "/") {
			prefix, err = netip.ParsePrefix(addr)
		} else {
			var a netip.Addr
			a, err = netip.ParseAddr(addr)
			if err == nil {
				prefix = netip.PrefixFrom(a, a.BitLen())
			}
		}
		if err != nil || !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return nil, errBadTCPAllow
		}
		out = append(out, tcpAllowRule{prefix: prefix.Masked(), lo: lo, hi: hi})
	}
	return out, nil
}

// tcpTargetAddr resolves a lease target host to the address the agent will
// dial, or returns a contract error code. "local" is 127.0.0.1.
func tcpTargetAddr(host string) (netip.Addr, bool, string) {
	if host == "local" {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1}), true, ""
	}
	a, err := netip.ParseAddr(host)
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false, "target_forbidden"
	}
	a = a.Unmap()
	// One spelling only: the canonical form the server signed.
	if a.String() != host {
		return netip.Addr{}, false, "target_forbidden"
	}
	if tcpForbidden(a) {
		return netip.Addr{}, false, "target_forbidden"
	}
	return a, false, ""
}

// tcpForbidden reports the always-refused classes, loopback included (a
// non-"local" target can never be loopback).
func tcpForbidden(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range tcpForbiddenPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// tcpAllowed checks the agent allowlist against the exact address dialed:
// "local" matches only local entries, an address only prefixes of its family.
func tcpAllowed(rules []tcpAllowRule, addr netip.Addr, local bool, port int) bool {
	for _, r := range rules {
		if port < r.lo || port > r.hi {
			continue
		}
		if local && r.local {
			return true
		}
		if !local && !r.local && r.prefix.Contains(addr) {
			return true
		}
	}
	return false
}
