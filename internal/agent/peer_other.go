//go:build !linux && !darwin

package agent

import "net"

// On Windows the socket lives in the user's profile, whose ACL already
// limits it to that user and administrators.
func peerAllowed(net.Conn) bool { return true }

func hardenProcess() {}
