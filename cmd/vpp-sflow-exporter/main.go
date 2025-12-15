package main

import (
	"context"
	"os"

	"go.uber.org/zap"

	"github.com/IPA-CyberLab/vpp-tools/cliutils"
	"github.com/IPA-CyberLab/vpp-tools/cmd/vpp-sflow-exporter/app"
)

func main() {
	if err := app.Command.Run(context.Background(), os.Args); err != nil {
		// omit stacktrace
		zap.L().WithOptions(zap.AddStacktrace(zap.FatalLevel)).Error(err.Error())
		os.Exit(cliutils.ExitCodeOfError(err))
	}
}
