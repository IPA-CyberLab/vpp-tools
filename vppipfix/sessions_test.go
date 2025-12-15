package vppipfix

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"testing"
	"time"
)

// MustParseFlow parses a conntrack -L like string into a Flow.
// Format: "tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80"
// The first src/dst/sport/dport are original, the second set are NAT-translated.
// Protocol can be "tcp" (6) or "udp" (17).
func MustParseFlow(s string) Flow {
	protoRe := regexp.MustCompile(`^(tcp|udp)\s+`)
	kvRe := regexp.MustCompile(`(src|dst|sport|dport)=(\S+)`)

	protoMatch := protoRe.FindStringSubmatch(s)
	if protoMatch == nil {
		panic(fmt.Sprintf("MustParseFlow: invalid protocol in %q", s))
	}

	var proto uint8
	switch protoMatch[1] {
	case "tcp":
		proto = 6
	case "udp":
		proto = 17
	}

	matches := kvRe.FindAllStringSubmatch(s, -1)
	if len(matches) != 8 {
		panic(fmt.Sprintf("MustParseFlow: expected 8 key=value pairs, got %d in %q", len(matches), s))
	}

	parseAddr := func(s string) netip.Addr {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			panic(fmt.Sprintf("MustParseFlow: invalid address %q: %v", s, err))
		}
		return addr
	}

	parsePort := func(s string) uint16 {
		port, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			panic(fmt.Sprintf("MustParseFlow: invalid port %q: %v", s, err))
		}
		return uint16(port)
	}

	// matches[0..3] are original, matches[4..7] are NAT
	return Flow{
		SrcAddr:    parseAddr(matches[0][2]),
		DstAddr:    parseAddr(matches[1][2]),
		SrcPort:    parsePort(matches[2][2]),
		DstPort:    parsePort(matches[3][2]),
		NatSrcAddr: parseAddr(matches[4][2]),
		NatDstAddr: parseAddr(matches[5][2]),
		NatSrcPort: parsePort(matches[6][2]),
		NatDstPort: parsePort(matches[7][2]),
		Protocol:   proto,
	}
}

func TestFlowHashH32(t *testing.T) {
	tests := []struct {
		name     string
		flow     Flow
		wantSame []Flow // flows that should produce the same hash
		wantDiff []Flow // flows that should produce a different hash
	}{
		{
			name: "basic flow",
			flow: MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80"),
			wantSame: []Flow{
				// Same NAT fields, different original fields - should hash the same
				MustParseFlow("tcp src=192.168.2.2 dst=10.0.0.2 sport=22222 dport=443 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80"),
			},
			wantDiff: []Flow{
				// Different NatDstAddr
				MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.2 sport=54321 dport=80"),
				// Different NatSrcPort
				MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=11111 dport=80"),
				// Different NatDstPort
				MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=8080"),
				// Different Protocol
				MustParseFlow("udp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := flowHashH32(&tt.flow)

			for i, sameFlow := range tt.wantSame {
				sameHash := flowHashH32(&sameFlow)
				if hash != sameHash {
					t.Errorf("wantSame[%d]: expected same hash, got %d vs %d", i, hash, sameHash)
				}
			}

			for i, diffFlow := range tt.wantDiff {
				diffHash := flowHashH32(&diffFlow)
				if hash == diffHash {
					t.Errorf("wantDiff[%d]: expected different hash, got same %d", i, hash)
				}
			}
		})
	}
}

func TestFlowHashH32_Deterministic(t *testing.T) {
	flow := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")

	hash1 := flowHashH32(&flow)
	hash2 := flowHashH32(&flow)

	if hash1 != hash2 {
		t.Errorf("hash is not deterministic: %d vs %d", hash1, hash2)
	}
}

func TestSessions_MultipleSessions(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	flow1 := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")
	flow2 := MustParseFlow("tcp src=192.168.1.2 dst=10.0.0.2 sport=22222 dport=443 src=203.0.113.2 dst=10.0.0.2 sport=33333 dport=443")

	t1 := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 12, 14, 10, 1, 0, 0, time.UTC)
	t3 := time.Date(2025, 12, 14, 10, 5, 0, 0, time.UTC)
	t4 := time.Date(2025, 12, 14, 10, 6, 0, 0, time.UTC)

	sessions.ObserveCreate(t1, &flow1)
	sessions.ObserveCreate(t2, &flow2)
	sessions.ObserveDelete(t3, &flow1)
	sessions.ObserveDelete(t4, &flow2)

	if len(reported) != 2 {
		t.Fatalf("expected 2 sessions reported, got %d", len(reported))
	}

	// First reported should be flow1
	if reported[0].Start != t1 || reported[0].End != t3 {
		t.Errorf("flow1 times mismatch: Start=%v End=%v", reported[0].Start, reported[0].End)
	}
	if !flowEqual(&reported[0].Flow, &flow1) {
		t.Errorf("flow1 mismatch")
	}

	// Second reported should be flow2
	if reported[1].Start != t2 || reported[1].End != t4 {
		t.Errorf("flow2 times mismatch: Start=%v End=%v", reported[1].Start, reported[1].End)
	}
	if !flowEqual(&reported[1].Flow, &flow2) {
		t.Errorf("flow2 mismatch")
	}
}
func TestSessions_DeleteWithoutCreate(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	flow := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")

	deleteTime := time.Date(2025, 12, 14, 10, 5, 0, 0, time.UTC)

	sessions.ObserveDelete(deleteTime, &flow)

	if len(reported) != 1 {
		t.Fatalf("expected 1 session reported, got %d", len(reported))
	}

	sess := reported[0]
	if !sess.Start.IsZero() {
		t.Errorf("expected Start to be zero, got %v", sess.Start)
	}
	if sess.End != deleteTime {
		t.Errorf("expected End=%v, got %v", deleteTime, sess.End)
	}
}

func TestSessions_DuplicateDelete(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	flow := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")

	createTime := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)
	deleteTime1 := time.Date(2025, 12, 14, 10, 5, 0, 0, time.UTC)
	deleteTime2 := time.Date(2025, 12, 14, 10, 6, 0, 0, time.UTC)

	sessions.ObserveCreate(createTime, &flow)
	sessions.ObserveDelete(deleteTime1, &flow)
	sessions.ObserveDelete(deleteTime2, &flow) // duplicate delete

	if len(reported) != 2 {
		t.Fatalf("expected 2 sessions reported (one matched, one orphan), got %d", len(reported))
	}

	// First should have both start and end
	if reported[0].Start != createTime {
		t.Errorf("first session Start mismatch")
	}
	if reported[0].End != deleteTime1 {
		t.Errorf("first session End mismatch")
	}

	// Second should be orphan delete (no matching create)
	if !reported[1].Start.IsZero() {
		t.Errorf("second session should have zero Start")
	}
	if reported[1].End != deleteTime2 {
		t.Errorf("second session End mismatch")
	}
}

func TestSessions_DuplicateCreate(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	flow := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")

	createTime1 := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)
	createTime2 := time.Date(2025, 12, 14, 10, 1, 0, 0, time.UTC)
	deleteTime := time.Date(2025, 12, 14, 10, 5, 0, 0, time.UTC)

	sessions.ObserveCreate(createTime1, &flow)
	sessions.ObserveCreate(createTime2, &flow) // duplicate create - should be ignored

	// There should only be 1 active session, not 2
	if sessions.ActiveCount() != 1 {
		t.Errorf("expected 1 active session after duplicate create, got %d", sessions.ActiveCount())
	}

	sessions.ObserveDelete(deleteTime, &flow)

	// Only one session should be reported
	if len(reported) != 1 {
		t.Fatalf("expected 1 session reported, got %d", len(reported))
	}

	// The session should use the first create time
	if reported[0].Start != createTime1 {
		t.Errorf("expected Start=%v, got %v", createTime1, reported[0].Start)
	}
	if reported[0].End != deleteTime {
		t.Errorf("expected End=%v, got %v", deleteTime, reported[0].End)
	}
}

func TestSessions_ReportAllStartBefore_RemoveStale(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	flow1 := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")
	flow2 := MustParseFlow("tcp src=192.168.1.2 dst=10.0.0.2 sport=22222 dport=443 src=203.0.113.2 dst=10.0.0.2 sport=33333 dport=443")
	flow3 := MustParseFlow("udp src=192.168.1.3 dst=10.0.0.3 sport=33333 dport=53 src=203.0.113.3 dst=10.0.0.3 sport=44444 dport=53")

	t1 := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 12, 14, 10, 5, 0, 0, time.UTC)
	t3 := time.Date(2025, 12, 14, 10, 10, 0, 0, time.UTC)
	threshold := time.Date(2025, 12, 14, 10, 7, 0, 0, time.UTC)

	sessions.ObserveCreate(t1, &flow1) // Before threshold
	sessions.ObserveCreate(t2, &flow2) // Before threshold
	sessions.ObserveCreate(t3, &flow3) // After threshold

	if sessions.ActiveCount() != 3 {
		t.Fatalf("expected 3 active sessions, got %d", sessions.ActiveCount())
	}

	sessions.ReportAllStartBefore(threshold, true) // removeStale=true

	// Should report 2 sessions (flow1 and flow2)
	if len(reported) != 2 {
		t.Fatalf("expected 2 sessions reported, got %d", len(reported))
	}

	// Only flow3 should remain active (stale sessions removed)
	if sessions.ActiveCount() != 1 {
		t.Errorf("expected 1 active session remaining, got %d", sessions.ActiveCount())
	}

	// Verify reported sessions have zero End time (incomplete sessions)
	for i, sess := range reported {
		if !sess.End.IsZero() {
			t.Errorf("reported[%d]: expected End to be zero, got %v", i, sess.End)
		}
	}

	// Verify one is flow1 and one is flow2 (order is not guaranteed due to map iteration)
	foundFlow1, foundFlow2 := false, false
	for _, sess := range reported {
		if flowEqual(&sess.Flow, &flow1) && sess.Start == t1 {
			foundFlow1 = true
		}
		if flowEqual(&sess.Flow, &flow2) && sess.Start == t2 {
			foundFlow2 = true
		}
	}
	if !foundFlow1 {
		t.Error("flow1 was not reported")
	}
	if !foundFlow2 {
		t.Error("flow2 was not reported")
	}
}

func TestSessions_ReportAllStartBefore_KeepActive(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	flow1 := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")
	flow2 := MustParseFlow("tcp src=192.168.1.2 dst=10.0.0.2 sport=22222 dport=443 src=203.0.113.2 dst=10.0.0.2 sport=33333 dport=443")

	t1 := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 12, 14, 10, 5, 0, 0, time.UTC)
	threshold := time.Date(2025, 12, 14, 10, 7, 0, 0, time.UTC)
	deleteTime := time.Date(2025, 12, 14, 10, 10, 0, 0, time.UTC)

	sessions.ObserveCreate(t1, &flow1)
	sessions.ObserveCreate(t2, &flow2)

	if sessions.ActiveCount() != 2 {
		t.Fatalf("expected 2 active sessions, got %d", sessions.ActiveCount())
	}

	sessions.ReportAllStartBefore(threshold, false) // removeStale=false (keep active)

	// Should report 2 sessions
	if len(reported) != 2 {
		t.Fatalf("expected 2 sessions reported, got %d", len(reported))
	}

	// Both sessions should still be active (not removed)
	if sessions.ActiveCount() != 2 {
		t.Errorf("expected 2 active sessions remaining, got %d", sessions.ActiveCount())
	}

	// Now simulate delete event for flow1 - should still work
	sessions.ObserveDelete(deleteTime, &flow1)

	// Should have reported 3 total (2 from ReportAllStartBefore + 1 from delete)
	if len(reported) != 3 {
		t.Fatalf("expected 3 sessions reported after delete, got %d", len(reported))
	}

	// The last reported session should have both start and end times
	lastReported := reported[2]
	if lastReported.Start != t1 {
		t.Errorf("expected last reported Start=%v, got %v", t1, lastReported.Start)
	}
	if lastReported.End != deleteTime {
		t.Errorf("expected last reported End=%v, got %v", deleteTime, lastReported.End)
	}

	// Only flow2 should remain active
	if sessions.ActiveCount() != 1 {
		t.Errorf("expected 1 active session after delete, got %d", sessions.ActiveCount())
	}
}

func TestSessions_ReportAllStartBefore_Empty(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	threshold := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)

	// Should not panic or report anything when empty
	sessions.ReportAllStartBefore(threshold, true)

	if len(reported) != 0 {
		t.Errorf("expected 0 sessions reported, got %d", len(reported))
	}
}

func TestSessions_ReportAllStartBefore_AllBefore(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	flow1 := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")
	flow2 := MustParseFlow("tcp src=192.168.1.2 dst=10.0.0.2 sport=22222 dport=443 src=203.0.113.2 dst=10.0.0.2 sport=33333 dport=443")

	t1 := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 12, 14, 10, 1, 0, 0, time.UTC)
	threshold := time.Date(2025, 12, 14, 10, 5, 0, 0, time.UTC)

	sessions.ObserveCreate(t1, &flow1)
	sessions.ObserveCreate(t2, &flow2)

	sessions.ReportAllStartBefore(threshold, true)

	if len(reported) != 2 {
		t.Fatalf("expected 2 sessions reported, got %d", len(reported))
	}

	if sessions.ActiveCount() != 0 {
		t.Errorf("expected 0 active sessions remaining, got %d", sessions.ActiveCount())
	}
}

func TestSessions_ReportAllStartBefore_NoneBeforeThreshold(t *testing.T) {
	var reported []Session
	sessions := NewSessions(func(sess Session) {
		reported = append(reported, sess)
	}, nil, nil)

	flow1 := MustParseFlow("tcp src=192.168.1.1 dst=10.0.0.1 sport=12345 dport=80 src=203.0.113.1 dst=10.0.0.1 sport=54321 dport=80")

	t1 := time.Date(2025, 12, 14, 10, 5, 0, 0, time.UTC)
	threshold := time.Date(2025, 12, 14, 10, 0, 0, 0, time.UTC)

	sessions.ObserveCreate(t1, &flow1)

	sessions.ReportAllStartBefore(threshold, true)

	if len(reported) != 0 {
		t.Fatalf("expected 0 sessions reported, got %d", len(reported))
	}

	if sessions.ActiveCount() != 1 {
		t.Errorf("expected 1 active session remaining, got %d", sessions.ActiveCount())
	}
}
