//go:build darwin

package agent

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// peerAllowed accepts only connections from processes of the same user.
func peerAllowed(conn net.Conn) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}
	allowed := false
	_ = raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		allowed = err == nil && int(cred.Uid) == os.Getuid()
	})
	return allowed
}

func hardenProcess() {}
