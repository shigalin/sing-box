package reuse

import (
	"errors"
	"net"
	"os"
	"testing"
)

func TestErrorReply(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err     error
		code    byte
		message string
	}{
		{errAFNotSupported, 0x01, "address family not supported"},
		{errNetDown, 0x02, "network is down"},
		{errNetUnreachable, 0x03, "network is unreachable"},
		{errConnReset, 0x04, "connection reset by peer"},
		{errTimedOut, 0x05, "connection timed out"},
		{os.ErrDeadlineExceeded, 0x05, "connection timed out"},
		{errConnRefused, 0x06, "connection refused"},
		{errHostUnreachable, 0x08, "host is unreachable"},
		{errors.New("other"), 0xff, "Unknown error"},
	} {
		t.Run(test.message, func(t *testing.T) {
			t.Parallel()
			wrapped := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: test.err}}
			code, message := ErrorReply(wrapped)
			if code != test.code || message != test.message {
				t.Fatalf("got (%#x, %q), want (%#x, %q)", code, message, test.code, test.message)
			}
		})
	}
}
