package main

import (
	"net"
	"strings"
	"testing"
)

// ipsAreSortedAsc is a numeric ascending check for
// IPv4 address strings. We can't use
// sort.StringsAreSorted because lexicographic
// comparison puts "192.168.40.10" before
// "192.168.40.2" (which is the wrong dial order —
// users expect to scan a /24 in numerical order).
func ipsAreSortedAsc(ips []string) bool {
	for i := 1; i < len(ips); i++ {
		a := net.ParseIP(ips[i-1]).To4()
		b := net.ParseIP(ips[i]).To4()
		if a == nil || b == nil {
			return false
		}
		ai := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		bi := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if ai > bi {
			return false
		}
	}
	return true
}

// TestParseCIDR_ClassC confirms a /24 yields the
// expected 254 hosts (network + broadcast skipped).
// This is the "happy path" — what most users will type.
func TestParseCIDR_ClassC(t *testing.T) {
	ips, err := parseScanCIDR("192.168.40.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 254 {
		t.Errorf("len(ips) = %d, want 254", len(ips))
	}
	// First must be 192.168.40.1, last 192.168.40.254.
	if ips[0] != "192.168.40.1" {
		t.Errorf("ips[0] = %q, want 192.168.40.1", ips[0])
	}
	if ips[253] != "192.168.40.254" {
		t.Errorf("ips[253] = %q, want 192.168.40.254", ips[253])
	}
	// Sorted numerically ascending (NOT lexicographic,
	// which would put 192.168.40.10 before 192.168.40.2).
	if !ipsAreSortedAsc(ips) {
		t.Error("ips not sorted ascending numerically")
	}
}

// TestParseCIDR_ClassB_BelowCap confirms a /22 yields
// 1022 hosts (just under the 1024 cap). This exercises
// the boundary between "accepted" and "rejected too
// large" — /22 = 1022, /21 = 2046 (rejected).
func TestParseCIDR_ClassB_BelowCap(t *testing.T) {
	ips, err := parseScanCIDR("172.16.0.0/22")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1022 {
		t.Errorf("len(ips) = %d, want 1022", len(ips))
	}
	if ips[0] != "172.16.0.1" {
		t.Errorf("ips[0] = %q, want 172.16.0.1", ips[0])
	}
	if ips[len(ips)-1] != "172.16.3.254" {
		t.Errorf("ips[last] = %q, want 172.16.3.254", ips[len(ips)-1])
	}
}

// TestParseCIDR_Slash31 covers RFC 3021 point-to-point
// — both addresses are usable, no skip.
func TestParseCIDR_Slash31(t *testing.T) {
	ips, err := parseScanCIDR("10.0.0.0/31")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Errorf("len(ips) = %d, want 2", len(ips))
	}
	if ips[0] != "10.0.0.0" || ips[1] != "10.0.0.1" {
		t.Errorf("ips = %v, want [10.0.0.0 10.0.0.1]", ips)
	}
}

// TestParseCIDR_Slash32 is the single-host case.
func TestParseCIDR_Slash32(t *testing.T) {
	ips, err := parseScanCIDR("203.0.113.42/32")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.42" {
		t.Errorf("ips = %v, want [203.0.113.42]", ips)
	}
}

// TestParseCIDR_RejectsTooLarge confirms the cap kicks
// in. /21 = 2046 hosts, which is over the 1024 cap.
// A user typing this gets a clear error instead of
// innerlink silently scanning 2k IPs and DoS'ing the
// LAN.
func TestParseCIDR_RejectsTooLarge(t *testing.T) {
	_, err := parseScanCIDR("10.0.0.0/21")
	if err == nil {
		t.Fatal("expected error for /21 (2046 hosts > 1024 cap)")
	}
	if !strings.Contains(err.Error(), "1024") {
		t.Errorf("error should mention the 1024 cap, got: %v", err)
	}
}

// TestParseCIDR_RejectsSlash0 covers the "scan the
// whole internet" foot-gun. /0 would enumerate every
// IPv4 — a denial-of-service against the local
// network and a useless result. We reject outright.
func TestParseCIDR_RejectsSlash0(t *testing.T) {
	_, err := parseScanCIDR("0.0.0.0/0")
	if err == nil {
		t.Fatal("expected error for /0")
	}
	if !strings.Contains(err.Error(), "/0") {
		t.Errorf("error should mention /0, got: %v", err)
	}
}

// TestParseCIDR_RejectsIPv6 covers the "is this v4
// or v6" check. The v0.5.1 implementation is
// IPv4-only because innerlink's transport and
// discovery are v4. Rejecting v6 with a clear
// message is better than silently producing an
// empty list.
func TestParseCIDR_RejectsIPv6(t *testing.T) {
	_, err := parseScanCIDR("fe80::/64")
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR")
	}
	if !strings.Contains(err.Error(), "IPv4") {
		t.Errorf("error should mention IPv4, got: %v", err)
	}
}

// TestParseCIDR_RejectsGarbage covers the standard
// "user mistyped something" path. We don't want to
// return an empty list; the error should name the
// bad input so the user can fix it.
func TestParseCIDR_RejectsGarbage(t *testing.T) {
	for _, bad := range []string{
		"",
		"not-a-cidr",
		"192.168.40.0",
		"192.168.40.0/",
		"192.168.40.0/33",
		"999.999.999.999/24",
	} {
		_, err := parseScanCIDR(bad)
		if err == nil {
			t.Errorf("parseScanCIDR(%q) returned nil err, want failure", bad)
		}
	}
}

// TestLocalIPs_IncludesLoopback is a sanity check
// that the always-include-127.0.0.1 logic is in
// place. Without it, an e2e test that scan's
// 127.0.0.0/24 would dial itself.
func TestLocalIPs_IncludesLoopback(t *testing.T) {
	ips := localIPs()
	if !ips["127.0.0.1"] {
		t.Error("localIPs missing 127.0.0.1 (e2e self-skip would dial own loopback)")
	}
}
