//go:build !windows

package reuse

import "syscall"

const (
	errAFNotSupported  = syscall.EAFNOSUPPORT
	errNetDown         = syscall.ENETDOWN
	errNetUnreachable  = syscall.ENETUNREACH
	errConnReset       = syscall.ECONNRESET
	errTimedOut        = syscall.ETIMEDOUT
	errConnRefused     = syscall.ECONNREFUSED
	errHostUnreachable = syscall.EHOSTUNREACH
)
