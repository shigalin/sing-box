package reuse

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestErrorReplyWinsock(t *testing.T) {
	t.Parallel()
	// Use the actual errors returned by Winsock, independently of the aliases
	// used by ErrorReply, so synthetic syscall errno values cannot pass.
	for _, test := range []struct {
		err  error
		code byte
	}{
		{windows.WSAEAFNOSUPPORT, 0x01},
		{windows.WSAENETDOWN, 0x02},
		{windows.WSAENETUNREACH, 0x03},
		{windows.WSAECONNRESET, 0x04},
		{windows.WSAETIMEDOUT, 0x05},
		{windows.WSAECONNREFUSED, 0x06},
		{windows.WSAEHOSTUNREACH, 0x08},
	} {
		wrapped := &net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connectex", Err: test.err}}
		if code, _ := ErrorReply(wrapped); code != test.code {
			t.Errorf("Winsock %v: got code %#x, want %#x", test.err, code, test.code)
		}
	}
}
