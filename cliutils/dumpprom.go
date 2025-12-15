package cliutils

import (
	"bytes"
	"path"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"go.uber.org/zap"
)

func DumpPrometheusMetrics(gatherer prometheus.Gatherer, filter string, logger *zap.Logger) {
	s := logger.Named("DumpPrometheusMetrics").Sugar()

	mfs, err := gatherer.Gather()
	if err != nil {
		s.Errorf("prometheus gather failed: %v", err)
		return
	}

	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		matched, err := path.Match(filter, mf.GetName())
		if err != nil {
			s.Errorf("invalid filter pattern: %v", err)
			return
		}
		if !matched {
			// s.Debugf("filtered out: %s", mf.GetName())
			continue
		}

		if err := enc.Encode(mf); err != nil {
			s.Errorf("prometheus encode failed: %v", err)
			return
		}
	}

	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			break
		}
		s.Info(line)
	}
}
