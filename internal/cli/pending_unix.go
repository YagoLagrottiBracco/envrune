//go:build linux || darwin

package cli

import "golang.org/x/sys/unix"

// discardPendingInput drains bytes already queued on the terminal after a
// secret prompt, such as the extra lines of a multi-line paste, so they are
// neither run as commands nor read by the next prompt. It reports whether
// anything was discarded.
func discardPendingInput(fd int) bool {
	n, err := unix.IoctlGetInt(fd, inputQueueRequest)
	if err != nil || n <= 0 {
		return false
	}
	pending := make([]byte, n)
	read, _ := unix.Read(fd, pending)
	wipe(pending)
	return read > 0
}
