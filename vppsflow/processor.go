package vppsflow

import (
	"bytes"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yzp0n/goflow2/decoders/sflow"
	"go.uber.org/zap"
)

type Processor struct {
	logger *zap.Logger

	droppedCount prometheus.Gauge
}

const PrometheusNamespace = "vppsflow"

func New(registerer prometheus.Registerer, logger *zap.Logger) (*Processor, error) {
	p := &Processor{
		logger: logger,

		droppedCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "dropsample",
			Name:      "dropped_count",
			Help:      "Total number of discarded packets which have been dropped due to rate limit or resource limit",
		}),
	}
	if err := registerer.Register(p.droppedCount); err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Processor) Process(bs []byte) error {
	s := p.logger.Named("Process").Sugar()
	_ = s

	buf := bytes.NewBuffer(bs)
	var sp sflow.Packet
	if err := sflow.DecodeMessageVersion(buf, &sp); err != nil {
		return fmt.Errorf("failed to decode sflow packet: %w", err)
	}

	/*
		j, err := json.MarshalIndent(sp, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to convert sflow packet to string: %w", err)
		}
		s.Debugf("sFlow packet: %s", j)
	*/

	for _, sampleI := range sp.Samples {
		switch sample := sampleI.(type) {
		case sflow.CounterSample:
			p.HandleCounterSample(&sample)
		case sflow.DropSample:
			p.HandleDropSample(&sample)
		default:
		}
	}

	return nil
}

func (p *Processor) HandleCounterSample(sample *sflow.CounterSample) {
	s := p.logger.Named("HandleCounterSample").Sugar()

	for _, record := range sample.Records {
		switch counters := record.Data.(type) {
		case *sflow.IfCounters:
			s.Infof("ifCounters: %+v", counters)
		case *sflow.EthernetCounters:
			s.Infof("ethernetCounters: %+v", counters)
		default:
		}
	}
}

func (p *Processor) HandleDropSample(sample *sflow.DropSample) {
	s := p.logger.Named("HandleDropSample").Sugar()
	_ = s

	p.droppedCount.Set(float64(sample.Drops))

	for _, rawrecord := range sample.Records {
		switch record := rawrecord.Data.(type) {
		case sflow.ExtendedACL:
			s.Infof("ExtendedACL: %+v", record)
		case sflow.ExtendedFunction:
			s.Infof("ExtendedFunction: %+v", record)
		case sflow.ExtendedHwTrap:
			s.Infof("ExtendedHwTrap: %+v", record)
		case sflow.ExtendedLinuxDropReason:
			s.Infof("ExtendedLinuxDropReason: %+v", record)
		default:
			s.Infof("Unknown drop record format: %d", rawrecord.Header.DataFormat)
		}
	}
}
