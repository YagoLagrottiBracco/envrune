//go:build !linux && !darwin && !windows

package agent

import "net"

// Other Unix systems give no portable way to read the peer's user; the
// socket's 0600 mode and private directory keep other users out.
func peerAllowed(net.Conn) bool { return true }

func hardenProcess() {}
