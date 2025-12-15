package vppipfix

import (
	"encoding/binary"
	"hash/fnv"
	"net/netip"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"go.uber.org/zap"
)

// Flow represents a NAT44 flow
type Flow struct {
	SrcAddr netip.Addr `json:"src_addr"`
	DstAddr netip.Addr `json:"dst_addr"`
	SrcPort uint16     `json:"src_port"`
	DstPort uint16     `json:"dst_port"`

	NatSrcAddr netip.Addr `json:"nat_src_addr"`
	NatDstAddr netip.Addr `json:"nat_dst_addr"`
	NatSrcPort uint16     `json:"nat_src_port"`
	NatDstPort uint16     `json:"nat_dst_port"`

	Protocol uint8 `json:"proto"`
}

// Session is a NAT44 flow with start and end times
type Session struct {
	Start time.Time `json:"start_time"`
	End   time.Time `json:"end_time"`

	Flow
}

func flowHashH32(f *Flow) uint32 {
	h32 := fnv.New32a()
	_, _ = h32.Write(f.NatDstAddr.AsSlice())
	ports := make([]byte, 5)
	binary.BigEndian.PutUint16(ports[0:2], f.NatSrcPort)
	binary.BigEndian.PutUint16(ports[2:4], f.NatDstPort)
	ports[4] = f.Protocol
	_, _ = h32.Write(ports)
	return h32.Sum32()
}

// flowHashImpl is replacable for testing purposes
var flowHashImpl = flowHashH32

// flowEqual returns true if two flows have identical fields
func flowEqual(a, b *Flow) bool {
	return a.SrcAddr.Compare(b.SrcAddr) == 0 &&
		a.DstAddr.Compare(b.DstAddr) == 0 &&
		a.SrcPort == b.SrcPort &&
		a.DstPort == b.DstPort &&
		a.NatSrcAddr.Compare(b.NatSrcAddr) == 0 &&
		a.NatDstAddr.Compare(b.NatDstAddr) == 0 &&
		a.NatSrcPort == b.NatSrcPort &&
		a.NatDstPort == b.NatDstPort &&
		a.Protocol == b.Protocol
}

// ReportSessionFunc is a callback function invoked when a session is ready to be reported.
// A session is reported when:
// - the session is completed, i.e., when a delete event is observed.
// - the session is incomplete, but hasn't been reported for a certain timeout period.
type ReportSessionFunc func(sess Session)

// Sessions tracks NAT44 session state by correlating create and delete events
// received from IPFIX records.
type Sessions struct {
	cb     ReportSessionFunc
	logger *zap.Logger

	mu   sync.Mutex
	impl map[uint32][]Session

	createCount           prometheus.Counter
	deleteCount           prometheus.Counter
	matchedCount          prometheus.Counter
	orphanDeletesCount    prometheus.Counter
	orphanCreatesCount    prometheus.Counter
	duplicateCreatesCount prometheus.Counter
	sessionDuration       *prometheus.HistogramVec
}

func NewSessions(cb ReportSessionFunc, registerer prometheus.Registerer, logger *zap.Logger) *Sessions {
	s := &Sessions{
		cb:     cb,
		logger: logger,
		impl:   make(map[uint32][]Session),

		createCount: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "sessions",
			Name:      "create_events_total",
			Help:      "Total number of NAT44 session create events observed",
		}),
		deleteCount: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "sessions",
			Name:      "delete_events_total",
			Help:      "Total number of NAT44 session delete events observed",
		}),
		matchedCount: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "sessions",
			Name:      "matched_total",
			Help:      "Total number of sessions successfully matched (DELETE found matching CREATE)",
		}),
		orphanDeletesCount: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "sessions",
			Name:      "orphan_deletes_total",
			Help:      "Total number of DELETE events with no matching CREATE (session started before collector)",
		}),
		orphanCreatesCount: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "sessions",
			Name:      "orphan_creates_total",
			Help:      "Total number of CREATE events reported without matching DELETE (stale/timed-out sessions)",
		}),
		duplicateCreatesCount: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "sessions",
			Name:      "duplicate_creates_total",
			Help:      "Total number of duplicate CREATE events ignored",
		}),
		sessionDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "sessions",
			Name:      "duration_seconds",
			Help:      "Histogram of completed session durations in seconds",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200},
		}, []string{"protocol"}),
	}
	if registerer != nil {
		registerer.MustRegister(
			s.createCount, s.deleteCount,
			s.matchedCount, s.orphanDeletesCount,
			s.orphanCreatesCount, s.duplicateCreatesCount,
			s.sessionDuration,
		)
	}
	return s
}

// ObserveCreate records a NAT44 session creation event. The observation time t
// represents when the session was created, and f contains the flow details
// including original and NAT-translated addresses/ports.
func (s *Sessions) ObserveCreate(t time.Time, f *Flow) {
	s.createCount.Inc()
	createN := int(getCounterValue(s.createCount))

	if s.logger != nil {
		s.logger.Debug("ObserveCreate",
			zap.Int("n", createN),
			zap.Time("t", t),
			zap.Any("flow", f),
		)
	}

	h := flowHashImpl(f)

	// Check if a session with the same flow already exists
	for _, sess := range s.impl[h] {
		if flowEqual(&sess.Flow, f) {
			// Duplicate create - ignore
			s.duplicateCreatesCount.Inc()
			return
		}
	}

	sess := Session{
		Start: t,
		End:   time.Time{},
		Flow:  *f,
	}

	s.mu.Lock()
	s.impl[h] = append(s.impl[h], sess)
	s.mu.Unlock()
}

// ActiveCount returns the number of active sessions (sessions that have been
// created but not yet deleted/completed).
func (s *Sessions) ActiveCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, sessions := range s.impl {
		count += len(sessions)
	}
	return count
}

// ObserveDelete records a NAT44 session deletion event. The observation time t
// represents when the session was deleted. This should trigger the callback
// with the complete session information if a matching create event was observed.
func (s *Sessions) ObserveDelete(t time.Time, f *Flow) {
	s.deleteCount.Inc()
	deleteN := int(getCounterValue(s.deleteCount))

	if s.logger != nil {
		s.logger.Debug("ObserveDelete",
			zap.Int("n", deleteN),
			zap.Time("t", t),
			zap.Any("flow", f),
		)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// FIXME: consider calling `s.cb` outside of the lock to avoid potential deadlocks

	h := flowHashImpl(f)

	sessions := s.impl[h]
	for i, sess := range sessions {
		if !sess.End.IsZero() {
			// already deleted
			continue
		}
		if !flowEqual(&sess.Flow, f) {
			continue
		}

		// Found matching session - complete and report it
		s.matchedCount.Inc()
		sess.End = t
		s.sessionDuration.WithLabelValues(protocolName(sess.Protocol)).Observe(sess.End.Sub(sess.Start).Seconds())
		s.cb(sess)

		// Remove from slice
		s.impl[h] = append(sessions[:i], sessions[i+1:]...)
		if len(s.impl[h]) == 0 {
			delete(s.impl, h)
		}
		return
	}

	// No matching create event found - report session with only end time
	s.orphanDeletesCount.Inc()
	sess := Session{
		Start: time.Time{},
		End:   t,
		Flow:  *f,
	}
	s.cb(sess)
}

// ReportAllStartBefore reports all sessions that were created before the given
// threshold time. These sessions are reported via the callback.
// If removeStale is true, reported sessions are removed from the session tracker.
func (s *Sessions) ReportAllStartBefore(threshold time.Time, removeStale bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// FIXME: Consider calling `s.cb` outside of the lock to avoid potential deadlocks

	for h, sessions := range s.impl {
		remaining := sessions[:0]
		for _, sess := range sessions {
			stale := false

			if sess.Start.Before(threshold) {
				s.cb(sess)
				stale = true
			}

			if removeStale && stale {
				// Orphan create - session timed out without matching delete
				s.orphanCreatesCount.Inc()
				// do not add to remaining
			} else {
				remaining = append(remaining, sess)
			}
		}

		if removeStale {
			if len(remaining) == 0 {
				delete(s.impl, h)
			} else {
				s.impl[h] = remaining
			}
		}
	}
}

// getCounterValue extracts the current value from a prometheus Counter
func getCounterValue(c prometheus.Counter) float64 {
	var m dto.Metric
	c.Write(&m)
	return m.GetCounter().GetValue()
}

// ActiveSessionInfo contains start time and protocol for an active session.
type ActiveSessionInfo struct {
	Start    time.Time
	Protocol uint8
}

// ActiveSessionInfos returns the start times and protocols of all active sessions.
// This is used by the collector to compute active session age histogram per protocol.
func (s *Sessions) ActiveSessionInfos() []ActiveSessionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	var infos []ActiveSessionInfo
	for _, sessions := range s.impl {
		for _, sess := range sessions {
			infos = append(infos, ActiveSessionInfo{
				Start:    sess.Start,
				Protocol: sess.Protocol,
			})
		}
	}
	return infos
}

// protocolName returns a human-readable protocol name for the given protocol number
func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	default:
		return "other"
	}
}
