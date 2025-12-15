package app

import (
	"context"
	"io"

	"github.com/urfave/cli/v3"
	"go.uber.org/zap"

	"github.com/IPA-CyberLab/vpp-tools/cliutils"
	"github.com/IPA-CyberLab/vpp-tools/cmd/vpp-sflow-exporter/serve"
)

var Command = &cli.Command{
	Name:  "vpp-sflow-exporter",
	Usage: "Read sflow packets from host-sflowd(vpp-sflow) and export them as Prometheus metrics",

	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "verbose",
			Usage: "enable verbose logging",
		},
	},

	Commands: []*cli.Command{
		serve.Command,
	},
	Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
		if err := cliutils.PrepLogger(cmd); err != nil {
			// Print error message to stderr
			cmd.Writer = cmd.ErrWriter

			// Suppress help message on app.Before() failure.
			cli.HelpPrinter = func(_ io.Writer, _ string, _ interface{}) {}
			return ctx, err
		}

		return ctx, nil
	},
	After: func(ctx context.Context, cmd *cli.Command) error {
		_ = zap.L().Sync()
		return nil
	},
}
