package vppipfix

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/yzp0n/goflow2/decoders/netflow"
	"github.com/yzp0n/goflow2/decoders/utils"
	"go.uber.org/zap"
)

type Processor struct {
	logger *zap.Logger

	nftemplates netflow.NetFlowTemplateSystem
	sessions    *Sessions

	packetsProcessed *prometheus.CounterVec
}

const PrometheusNamespace = "vppipfix"

func New(reportfn ReportSessionFunc, registerer prometheus.Registerer, logger *zap.Logger) (*Processor, error) {
	p := &Processor{
		logger: logger,

		nftemplates: netflow.CreateTemplateSystem(),

		sessions: NewSessions(reportfn, registerer, logger.Named("Sessions")),

		packetsProcessed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: PrometheusNamespace,
			Subsystem: "collector",
			Name:      "packets_processed_total",
			Help:      "Total number of IPFIX packets processed by outcome",
		}, []string{"outcome"}),
	}
	if registerer != nil {
		collector := newCollector(p)
		if err := registerer.Register(collector); err != nil {
			return nil, err
		}
		if err := registerer.Register(p.packetsProcessed); err != nil {
			return nil, err
		}
	}

	return p, nil
}

const (
	NAT44_SESSION_CREATE = 4
	NAT44_SESSION_DELETE = 5
)

func (p *Processor) Process(bs []byte) error {
	s := p.logger.Named("Process").Sugar()

	buf := bytes.NewBuffer(bs)

	var version uint16
	if err := utils.BinaryDecoder(buf,
		&version,
	); err != nil {
		p.packetsProcessed.WithLabelValues("error_decode_version").Inc()
		return fmt.Errorf("failed to decode IPFIX version: %w", err)
	}

	if version != 10 {
		p.packetsProcessed.WithLabelValues("error_unsupported_version").Inc()
		return fmt.Errorf("unsupported IPFIX version: %d", version)
	}

	var packet netflow.IPFIXPacket
	err := netflow.DecodeMessageIPFIX(buf, p.nftemplates, &packet)
	if err != nil {
		p.packetsProcessed.WithLabelValues("error_decode_ipfix").Inc()
		return err
	}

	flowCount := 0
	hasTemplate := false

	for _, fs := range packet.FlowSets {
		switch fs := fs.(type) {
		case netflow.IPFIXOptionsTemplateFlowSet:
			hasTemplate = true
		case netflow.DataFlowSet:
			for _, r := range fs.Records {
				if len(r.Values) < 2 {
					continue
				}

				sv := r.Values[1]
				if sv.Type != netflow.IPFIX_FIELD_natEvent {
					continue
				}
				nebs, ok := sv.Value.([]byte)
				if !ok {
					s.Panicf("Unexpected value type for natEvent field: %T", sv.Value)
					continue
				}
				neInt := nebs[0]
				if neInt != NAT44_SESSION_CREATE && neInt != NAT44_SESSION_DELETE {
					s.Infof("Skipping non-session-create/delete natEvent: %d", neInt)
					continue
				}

				var observationT time.Time
				var flow Flow

				for _, v := range r.Values {
					bs, ok := v.Value.([]byte)
					if !ok {
						s.Panicf("Unexpected value type for field %d: %T", v.Type, v.Value)
						continue
					}

					switch v.Type {
					case netflow.IPFIX_FIELD_observationTimeMilliseconds:
						ms := binary.BigEndian.Uint64(bs)
						observationT = time.Unix(int64(ms/1000), int64(ms%1000)*1_000_000)
					case netflow.IPFIX_FIELD_sourceIPv4Address:
						flow.SrcAddr = netip.AddrFrom4([4]byte(bs[0:4]))
					case netflow.IPFIX_FIELD_destinationIPv4Address:
						flow.DstAddr = netip.AddrFrom4([4]byte(bs[0:4]))
					case netflow.IPFIX_FIELD_sourceTransportPort:
						flow.SrcPort = binary.BigEndian.Uint16(bs)
					case netflow.IPFIX_FIELD_destinationTransportPort:
						flow.DstPort = binary.BigEndian.Uint16(bs)
					case netflow.IPFIX_FIELD_postNATSourceIPv4Address:
						flow.NatSrcAddr = netip.AddrFrom4([4]byte(bs[0:4]))
					case netflow.IPFIX_FIELD_postNATDestinationIPv4Address:
						flow.NatDstAddr = netip.AddrFrom4([4]byte(bs[0:4]))
					case netflow.IPFIX_FIELD_postNAPTSourceTransportPort:
						flow.NatSrcPort = binary.BigEndian.Uint16(bs)
					case netflow.IPFIX_FIELD_postNAPTDestinationTransportPort:
						flow.NatDstPort = binary.BigEndian.Uint16(bs)
					case netflow.IPFIX_FIELD_protocolIdentifier:
						flow.Protocol = bs[0]
					}
				}

				switch neInt {
				case NAT44_SESSION_CREATE:
					p.sessions.ObserveCreate(observationT, &flow)
					flowCount++
				case NAT44_SESSION_DELETE:
					p.sessions.ObserveDelete(observationT, &flow)
					flowCount++
				default:
					s.Panicf("Unexpected natEvent value: %d", neInt)
				}
			}
		}
	}

	// Record successful packet processing with appropriate labels
	if hasTemplate && flowCount > 0 {
		p.packetsProcessed.WithLabelValues("success_template_and_flows").Inc()
	} else if hasTemplate {
		p.packetsProcessed.WithLabelValues("success_template").Inc()
	} else if flowCount == 0 {
		p.packetsProcessed.WithLabelValues("empty").Inc()
	} else {
		p.packetsProcessed.WithLabelValues("success_with_flows").Inc()
	}

	return nil
}

func (p *Processor) CheckIn(longActiveReportingThreshold, inactivityThreshold time.Time) {
	p.sessions.ReportAllStartBefore(longActiveReportingThreshold, false)
	p.sessions.ReportAllStartBefore(inactivityThreshold, true)
}
