//go:build darwin

package cli

// FIONREAD, _IOR('f', 127, int), which golang.org/x/sys/unix does not export.
const inputQueueRequest = 0x4004667f
