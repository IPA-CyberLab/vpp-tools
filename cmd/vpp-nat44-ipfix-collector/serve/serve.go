package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/IPA-CyberLab/vpp-tools/cliutils"
	"github.com/IPA-CyberLab/vpp-tools/kafkapusher"
	"github.com/IPA-CyberLab/vpp-tools/vppipfix"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
)

type UDPPacketPayloadInput struct {
	Bs []byte
}

type CheckpointInput struct {
	LongActiveThreshold time.Time
	InactivityThreshold time.Time
}

func listenIPFIX(ctx context.Context, addr string, chInput chan<- interface{}) error {
	s := zap.S().Named("listenIPFIX").With("addr", addr)

	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	defer l.Close()
	s.Infof("Listening for IPFIX packets on %s", addr)

	go func() {
		<-ctx.Done()

		s.Infof("Shutting down IPFIX listener on %s", addr)
		if err := l.Close(); err != nil {
			s.Errorf("Failed to close listener: %v", err)
		} else {
			s.Infof("Listener closed: %s", addr)
		}
	}()

	for {
		buf := make([]byte, 65535)
		n, _, err := l.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.Infof("Listener closed: %s", addr)
				break
			}
			return fmt.Errorf("failed to read from %s: %w", addr, err)
		}
		s.Debugf("Received %d bytes from %s", n, addr)
		packet := buf[:n]
		chInput <- UDPPacketPayloadInput{Bs: packet}
		s.Debugf("Packet sent to channel, length: %d", len(packet))
	}

	return context.Cause(ctx)
}

func readPcapFile(path string, nlimit int, longActiveReportingInterval, inactivityTimeout time.Duration, chInput chan<- interface{}) error {
	s := zap.S().Named("readPcapFile").With("path", path)

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	pcapr, err := pcapgo.NewReader(f)
	if err != nil {
		return err
	}

	// Virtual time tracking for CheckpointInput injection
	var lastCheckpointTime time.Time
	var lastPacketTime time.Time
	checkinDuration := 5 * time.Minute
	if longActiveReportingInterval < checkinDuration {
		checkinDuration = longActiveReportingInterval
	}

	// Override NowImpl to use lastPacketTime as current time
	vppipfix.NowImpl = func() time.Time { return lastPacketTime }

	for {
		nlimit -= 1
		if nlimit <= 0 {
			s.Infof("Reached packet limit, stopping reading pcap file: %s", path)
			break
		}

		raweth, ci, err := pcapr.ReadPacketData()
		if err != nil {
			if errors.Is(err, io.EOF) {
				s.Infof("Reached end of pcap file: %s", path)
				break
			}
			return fmt.Errorf("failed to ReadPacketData: %w", err)
		}
		s.Debugf("Read packet: %d bytes, captured at %s", len(raweth), ci.Timestamp)

		// Inject CheckpointInput based on virtual time progression
		if lastCheckpointTime.IsZero() {
			lastCheckpointTime = ci.Timestamp
		}
		for ci.Timestamp.Sub(lastCheckpointTime) >= checkinDuration {
			lastCheckpointTime = lastCheckpointTime.Add(checkinDuration)
			s.Infof("Virtual time checkpoint at %v: reporting long-active sessions started before %v, "+
				"removing inactive sessions last active before %v",
				lastCheckpointTime,
				lastCheckpointTime.Add(-longActiveReportingInterval),
				lastCheckpointTime.Add(-inactivityTimeout))
			chInput <- CheckpointInput{
				LongActiveThreshold: lastCheckpointTime.Add(-longActiveReportingInterval),
				InactivityThreshold: lastCheckpointTime.Add(-inactivityTimeout),
			}
		}
		lastPacketTime = ci.Timestamp

		packet := gopacket.NewPacket(raweth, layers.LayerTypeEthernet, gopacket.Default)
		ls := packet.Layers()
		if len(ls) < 3 {
			s.Debugf("Skipping packet with too few layers: %d", len(ls))
			continue
		}
		if ls[1].LayerType() != layers.LayerTypeIPv4 {
			s.Debugf("Skipping non-IPv4 packet: %s", ls[1].LayerType())
			continue
		}
		if ls[2].LayerType() != layers.LayerTypeUDP {
			s.Debugf("Skipping non-UDP packet: %s", ls[2].LayerType())
			continue
		}
		udp := ls[2].(*layers.UDP)

		chInput <- UDPPacketPayloadInput{Bs: udp.Payload}
	}

	// Final checkpoint to flush remaining sessions at end of pcap
	if !lastPacketTime.IsZero() {
		s.Infof("Final virtual time checkpoint at %v: flushing all remaining sessions", lastPacketTime)
		chInput <- CheckpointInput{
			LongActiveThreshold: lastPacketTime.Add(-longActiveReportingInterval),
			InactivityThreshold: lastPacketTime,
		}
	}

	return nil
}

var Command = &cli.Command{
	Name:                      "serve",
	Usage:                     "Run VPP NAT44 IPFIX Collector server",
	DisableSliceFlagSeparator: true,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "listenIPFIX",
			Usage: "Listen for IPFIX packets on this address:port",
			Value: ":4739",
		},
		&cli.StringFlag{
			Name:  "pcapFile",
			Usage: "Inject IPFIX packets from a pcap file instead of listening on a network interface",
		},
		&cli.IntFlag{
			Name:  "limit",
			Usage: "Limit the number of packets to read from the pcap file",
		},
		&cli.StringFlag{
			Name:  "dumpMetrics",
			Usage: "Dump prometheus metrics matching this filter pattern at exit (e.g., '*' for all metrics)",
		},
		&cli.StringFlag{
			Name:  "listen",
			Usage: "Listen for HTTP requests on this address:port",
			Value: ":8080",
		},
		&cli.StringFlag{
			Name:  "kafkaBroker",
			Usage: "kafkaBroker is the address of the Kafka broker to send events to. If not set, events will not be sent to Kafka.",
		},
		&cli.StringFlag{
			Name:  "kafkaTopic",
			Usage: "kafkaTopic is the topic to send events to. This must be set if kafkaBroker is set.",
		},
		&cli.DurationFlag{
			Name:  "longActiveReportingInterval",
			Usage: "Interval for reporting long-active sessions that have not been closed yet.",
			Value: 5 * time.Minute,
		},
		&cli.DurationFlag{
			Name:  "inactivityTimeout",
			Usage: "Duration of inactivity after which a session is considered ended and reported.",
			Value: 120 * time.Minute,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		logger := zap.L()
		s := logger.Named("vpp-nat44-ipfix-collector.serve").Sugar()

		if cmd.Duration("inactivityTimeout") < cmd.Duration("longActiveReportingInterval") {
			return fmt.Errorf("inactivityTimeout must be greater than or equal to longActiveReportingInterval")
		}

		kafkaBroker := cmd.String("kafkaBroker")
		kafkaTopic := cmd.String("kafkaTopic")
		if kafkaBroker != "" && kafkaTopic == "" {
			return fmt.Errorf("kafkaTopic must be set if kafkaBroker is set")
		}

		chSessions := make(chan vppipfix.Session, 100)
		reportfn := func(sess vppipfix.Session) {
			chSessions <- sess
		}

		proc, err := vppipfix.New(reportfn, prometheus.DefaultRegisterer, logger)
		if err != nil {
			return err
		}

		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		})
		mux.Handle("/metrics", promhttp.Handler())

		httpSrv := &http.Server{
			Addr:    cmd.String("listen"),
			Handler: mux,
		}

		ctx, cancel := context.WithCancelCause(ctx)
		cliutils.CancelOnSignal(cancel)

		httpSrvC := make(chan error, 1)
		go func() {
			s := zap.L().Named("httpServer").Sugar()
			s.Infof("Starting HTTP server on %s", httpSrv.Addr)
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				httpSrvC <- err
			}
			close(httpSrvC)
		}()
		go func() {
			<-ctx.Done()
			s.Infof("Shutting down HTTP server gracefully")
			if err := httpSrv.Shutdown(context.Background()); err != nil {
				s.Errorf("Failed to shutdown HTTP server: %v", err)
			} else {
				s.Infof("HTTP server stopped")
			}
		}()

		chInput := make(chan interface{}, 100)

		longActiveReportingInterval := cmd.Duration("longActiveReportingInterval")
		inactivityTimeout := cmd.Duration("inactivityTimeout")

		listenC := make(chan error, 1)
		if pcapFile := cmd.String("pcapFile"); pcapFile != "" {
			nlimit := cmd.Int("limit")
			if nlimit <= 0 {
				nlimit = math.MaxInt
			}
			go func() {
				s := zap.L().Named("pcapReader").Sugar()
				err := readPcapFile(pcapFile, nlimit, longActiveReportingInterval, inactivityTimeout, chInput)
				if err != nil {
					s.Errorf("Error reading pcap file %s: %v", pcapFile, err)
				}
				close(chInput)
			}()
			go func() {
				<-ctx.Done()
				close(listenC)
			}()
		} else if listenAddr := cmd.String("listenIPFIX"); listenAddr != "" {
			s.Infof("Listening for IPFIX packets on %s", listenAddr)
			go func() {
				listenC <- listenIPFIX(ctx, listenAddr, chInput)
				close(listenC)
			}()

			go func() {
				// If longActiveReportingInterval is set, make sure checkin is frequent enough.
				checkinDuration := 5 * time.Minute
				if longActiveReportingInterval < checkinDuration {
					checkinDuration = longActiveReportingInterval
				}

				checkinC := time.Tick(checkinDuration)
				for {
					select {
					case <-checkinC:
						longActiveReportingThreshold := time.Now().Add(-longActiveReportingInterval)
						inactivityThreshold := time.Now().Add(-inactivityTimeout)
						s.Infof("Enqueuing reporting of long-active sessions started before %v (%v ago), and "+
							"removing inactive sessions last active before %v (%v ago)",
							longActiveReportingThreshold, longActiveReportingInterval,
							inactivityThreshold, inactivityTimeout)

						chInput <- CheckpointInput{
							LongActiveThreshold: longActiveReportingThreshold,
							InactivityThreshold: inactivityThreshold,
						}

					case <-ctx.Done():
						return
					}
				}
			}()
		}

		procC := make(chan error, 1)
		go func() {
			s := zap.L().Named("runner[processor]").Sugar()
			for {
				select {
				case in := <-chInput:
					if in == nil {
						s.Infof("IPFIX packet channel closed")
					} else {
						switch in := in.(type) {
						case UDPPacketPayloadInput:
							if err := proc.Process(in.Bs); err != nil {
								s.Errorf("Failed to process IPFIX packet: %v", err)
							}
							continue
						case CheckpointInput:
							proc.CheckIn(in.LongActiveThreshold, in.InactivityThreshold)
							continue
						}
					}
				case <-ctx.Done():
				}

				close(procC)
				close(chSessions)
				break
			}
		}()

		pushC := make(chan error, 1)
		go func() {
			s := zap.L().Named("runner[pusher]").Sugar()

			if kafkaBroker != "" {
				kp, err := kafkapusher.New("vpp-nat44-ipfix-collector", kafkaBroker, kafkaTopic, logger)
				if err != nil {
					pushC <- fmt.Errorf("failed to create Kafka pusher: %w", err)
					close(pushC)
					return
				}

				for sess := range chSessions {
					bs, err := json.Marshal(sess)
					if err != nil {
						s.Errorf("Failed to marshal session to JSON: %v", err)
						continue
					}

					if err := kp.Push(ctx, bs); err != nil {
						s.Errorf("Failed to push session to Kafka: %v", err)
					}
				}
				kp.Close()
			} else {
				s.Info("Kafka not configured. Dump to logger instead.")

				for sess := range chSessions {
					bs, err := json.Marshal(sess)
					if err != nil {
						s.Errorf("Failed to marshal session to JSON: %v", err)
						continue
					}

					s.Infof("Reported session: %s", string(bs))
				}
			}
			close(pushC)
		}()

		select {
		case err := <-httpSrvC:
			if errors.Is(err, http.ErrServerClosed) {
				cancel(fmt.Errorf("HTTP server error: %w", err))
			}

		case err := <-listenC:
			if err != nil {
				cancel(fmt.Errorf("IPFIX listener error: %w", err))
			}

		case err := <-procC:
			if err != nil {
				cancel(fmt.Errorf("processor error: %w", err))
			}

		case err := <-pushC:
			if err != nil {
				cancel(fmt.Errorf("kafka pusher error: %w", err))
			}

		case <-ctx.Done():
		}
		cancel(nil)

		<-httpSrvC
		s.Infof("HTTP server joined")
		<-listenC
		s.Infof("IPFIX listener joined")
		<-procC
		s.Infof("Processor joined")
		<-pushC
		s.Infof("Pusher joined")
		<-ctx.Done()

		if filter := cmd.String("dumpMetrics"); filter != "" {
			cliutils.DumpPrometheusMetrics(prometheus.DefaultGatherer, filter, logger)
		}
		return context.Cause(ctx)
	},
}
