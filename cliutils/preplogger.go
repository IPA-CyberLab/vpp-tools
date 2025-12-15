package cliutils

import (
	"github.com/urfave/cli/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func PrepLogger(cmd *cli.Command) error {
	var logger *zap.Logger
	if loggeri, ok := cmd.Metadata["Logger"]; ok {
		logger = loggeri.(*zap.Logger)
	} else {
		cfg := zap.NewProductionConfig()
		if cmd.Bool("verbose") {
			cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
		}
		cfg.DisableCaller = true
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		//cfg.Encoding = "console"

		var err error
		logger, err = cfg.Build(
			zap.AddStacktrace(zap.NewAtomicLevelAt(zap.DPanicLevel)))
		if err != nil {
			return err
		}
	}
	zap.ReplaceGlobals(logger)

	return nil
}
