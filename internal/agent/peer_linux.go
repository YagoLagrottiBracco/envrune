//go:build linux

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
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		allowed = err == nil && int(cred.Uid) == os.Getuid()
	})
	return allowed
}

func hardenProcess() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
