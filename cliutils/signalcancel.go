package cliutils

import (
	"context"
	"errors"
	"os/signal"
	"syscall"
)

var ErrGracefulShutdown = errors.New("graceful shutdown")

func CancelOnSignal(cancelCause context.CancelCauseFunc) {
	go func() {
		sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		<-sigCtx.Done()
		cancelCause(ErrGracefulShutdown)
		stop()
	}()
}
