package main

import "testing"

func TestCheckSysServicePolicy(t *testing.T) {
	prev := sysServices
	t.Cleanup(func() { sysServices = prev })

	// Unsupported platform / absent capability fails closed.
	sysServices = func() ServiceManager { return &fakeServiceMgr{avail: false} }
	if err := checkSysServicePolicy("nginx.service", "restart"); err != errSysUnsupported {
		t.Fatalf("absent capability: got %v, want %v", err, errSysUnsupported)
	}

	sysServices = func() ServiceManager { return &fakeServiceMgr{avail: true} }

	// A verb outside the closed set is refused (Phase 1 is restart only).
	for _, verb := range []string{"stop", "start", "enable", "disable", ""} {
		if err := checkSysServicePolicy("nginx.service", verb); err != errSysBadAction {
			t.Fatalf("verb %q: got %v, want %v", verb, err, errSysBadAction)
		}
	}

	// A badly shaped unit name is refused.
	for _, unit := range []string{"", "nginx\n.service", "has space", "-leading", string(make([]byte, 200))} {
		if err := checkSysServicePolicy(unit, "restart"); err != errSysUnitDenied {
			t.Fatalf("unit %q: got %v, want %v", unit, err, errSysUnitDenied)
		}
	}

	// A well-shaped unit with restart on a capable host is allowed.
	if err := checkSysServicePolicy("nginx.service", "restart"); err != nil {
		t.Fatalf("good case: %v", err)
	}
}
