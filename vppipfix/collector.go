package vppipfix

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var NowImpl = time.Now

// Default histogram buckets for session age in seconds
var activeSessionAgeBuckets = []float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200}

type collector struct {
	p *Processor

	sessionsTotalDesc    *prometheus.Desc
	activeSessionAgeDesc *prometheus.Desc
}

func newCollector(p *Processor) *collector {
	return &collector{
		p: p,

		sessionsTotalDesc: prometheus.NewDesc(
			prometheus.BuildFQName(PrometheusNamespace, "sessions", "total"),
			"Total number of active NAT44 sessions",
			nil,
			nil,
		),
		activeSessionAgeDesc: prometheus.NewDesc(
			prometheus.BuildFQName(PrometheusNamespace, "sessions", "active_age_seconds"),
			"Histogram of active session ages in seconds at scrape time",
			[]string{"protocol"},
			nil,
		),
	}
}

func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.sessionsTotalDesc
	ch <- c.activeSessionAgeDesc
}

func (c *collector) Collect(ch chan<- prometheus.Metric) {
	now := NowImpl()
	infos := c.p.sessions.ActiveSessionInfos()

	// Report active session count
	ch <- prometheus.MustNewConstMetric(
		c.sessionsTotalDesc,
		prometheus.GaugeValue,
		float64(len(infos)),
	)

	// Group sessions by protocol
	type histData struct {
		count   uint64
		sum     float64
		buckets map[float64]uint64
	}
	perProtocol := make(map[string]*histData)

	for _, info := range infos {
		proto := protocolName(info.Protocol)
		if perProtocol[proto] == nil {
			buckets := make(map[float64]uint64)
			for _, b := range activeSessionAgeBuckets {
				buckets[b] = 0
			}
			perProtocol[proto] = &histData{buckets: buckets}
		}
		data := perProtocol[proto]

		age := now.Sub(info.Start).Seconds()
		data.count++
		data.sum += age

		// Increment all buckets where age <= bucket boundary
		for _, b := range activeSessionAgeBuckets {
			if age <= b {
				data.buckets[b]++
			}
		}
	}

	// Emit histogram for each protocol
	for proto, data := range perProtocol {
		ch <- prometheus.MustNewConstHistogram(
			c.activeSessionAgeDesc,
			data.count,   // count
			data.sum,     // sum
			data.buckets, // buckets
			proto,        // label value
		)
	}
}
