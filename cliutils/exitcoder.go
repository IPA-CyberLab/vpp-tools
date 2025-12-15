package cliutils

import "errors"

type ExitCoder interface {
	ExitCode() int
}

func ExitCodeOfError(err error) int {
	for {
		if ec, ok := err.(ExitCoder); ok {
			return ec.ExitCode()
		}

		if err = errors.Unwrap(err); err == nil {
			break
		}
	}

	return 1
}
