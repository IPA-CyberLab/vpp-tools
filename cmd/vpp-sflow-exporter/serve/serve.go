package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"

	"github.com/IPA-CyberLab/vpp-tools/cliutils"
	"github.com/IPA-CyberLab/vpp-tools/vppsflow"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
)

func listenSflow(ctx context.Context, addr string, chSflowPackets chan<- []byte) error {
	s := zap.S().Named("listenSflow").With("addr", addr)

	l, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	defer l.Close()
	s.Infof("Listening for sFlow packets on %s", addr)

	go func() {
		<-ctx.Done()

		s.Infof("Shutting down sFlow listener on %s", addr)
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
		chSflowPackets <- packet
		s.Debugf("Packet sent to channel, length: %d", len(packet))
	}

	return context.Cause(ctx)
}

func readPcapFile(path string, nlimit int, chSflowPackets chan<- []byte) error {
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

	for {
		nlimit -= 1
		if nlimit <= 0 {
			s.Infof("Reached packet limit, stopping reading pcap file: %s", path)
			return nil
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

		packet := gopacket.NewPacket(raweth, layers.LayerTypeEthernet, gopacket.Default)
		ls := packet.Layers()
		if len(ls) < 3 {
			s.Debugf("Skipping packet with too few layers: %d", len(ls))
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

		chSflowPackets <- udp.Payload
	}

	return nil
}

var Command = &cli.Command{
	Name:                      "serve",
	Usage:                     "Run VPP sFlow Exporter server",
	DisableSliceFlagSeparator: true,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "listenSflow",
			Usage: "Listen for sflow packets on this address:port",
			Value: ":6343",
		},
		&cli.StringFlag{
			Name:  "pcapFile",
			Usage: "Inject sflow packets from a pcap file instead of listening on a network interface",
		},
		&cli.StringFlag{
			Name:  "dumpMetrics",
			Usage: "Dump prometheus metrics matching this filter pattern at exit (e.g., '*' for all metrics)",
		},
		&cli.IntFlag{
			Name:  "limit",
			Usage: "Limit the number of packets to read from the pcap file",
		},
		&cli.StringFlag{
			Name:  "listen",
			Usage: "Listen for HTTP requests on this address:port",
			Value: ":8080",
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		logger := zap.L()
		s := logger.Named("vpp-sflow-exporter.serve").Sugar()

		chSflowPackets := make(chan []byte, 100)

		proc, err := vppsflow.New(prometheus.DefaultRegisterer, logger)
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

		listenC := make(chan error, 1)
		listenAddr := cmd.String("listenSflow")
		if listenAddr == "" {
			s.Warnf("sflow listener disabled, no packets will be received")
		} else {
			s.Infof("Listening for sflow packets on %s", listenAddr)
			go func() {
				listenC <- listenSflow(ctx, listenAddr, chSflowPackets)
				close(listenC)
			}()
		}

		pcapFile := cmd.String("pcapFile")
		if pcapFile != "" {
			nlimit := cmd.Int("limit")
			if nlimit <= 0 {
				nlimit = math.MaxInt
			}
			go func() {
				s := zap.L().Named("pcapReader").Sugar()
				err := readPcapFile(pcapFile, nlimit, chSflowPackets)
				if err != nil {
					s.Errorf("Error reading pcap file %s: %v", pcapFile, err)
				}
				close(chSflowPackets)
			}()
		}

		procC := make(chan error, 1)
		go func() {
			s := zap.L().Named("runner[processor]").Sugar()
			for {
				select {
				case bs := <-chSflowPackets:
					if bs == nil {
						s.Infof("sFlow packet channel closed")
					} else {
						if err := proc.Process(bs); err != nil {
							s.Errorf("Failed to process sFlow packet: %v", err)
						}
						continue
					}

				case <-ctx.Done():
				}

				close(procC)
				break
			}
		}()

		select {
		case err := <-httpSrvC:
			if errors.Is(err, http.ErrServerClosed) {
				cancel(fmt.Errorf("HTTP server error: %w", err))
			}

		case err := <-listenC:
			if err != nil {
				cancel(fmt.Errorf("sflow listener error: %w", err))
			}

		case err := <-procC:
			if err != nil {
				cancel(fmt.Errorf("processor error: %w", err))
			}

		case <-ctx.Done():
		}
		cancel(nil)

		if filter := cmd.String("dumpMetrics"); filter != "" {
			cliutils.DumpPrometheusMetrics(prometheus.DefaultGatherer, filter, logger)
		}

		<-httpSrvC
		s.Infof("HTTP server joined")
		<-listenC
		s.Infof("sFlow listener joined")
		<-procC
		s.Infof("Processor joined")
		<-ctx.Done()

		err = context.Cause(ctx)
		cancel(nil)
		return err
	},
}
