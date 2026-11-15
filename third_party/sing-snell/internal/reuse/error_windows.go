package reuse

import "golang.org/x/sys/windows"

// Windows socket operations return Winsock codes, not syscall's synthetic
// POSIX errno constants.
const (
	errAFNotSupported  = windows.WSAEAFNOSUPPORT
	errNetDown         = windows.WSAENETDOWN
	errNetUnreachable  = windows.WSAENETUNREACH
	errConnReset       = windows.WSAECONNRESET
	errTimedOut        = windows.WSAETIMEDOUT
	errConnRefused     = windows.WSAECONNREFUSED
	errHostUnreachable = windows.WSAEHOSTUNREACH
)
