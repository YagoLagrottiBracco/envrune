//go:build linux

package cli

import "golang.org/x/sys/unix"

const inputQueueRequest = unix.TIOCINQ
