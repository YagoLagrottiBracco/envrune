//go:build linux

package vault

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type vaultLock struct{ file *os.File }

func acquireLock(path string) (*vaultLock, error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrCannotUnlock
		}
		return nil, err
	}
	return &vaultLock{file: f}, nil
}
func (l *vaultLock) Close() {
	if l != nil {
		_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
		_ = l.file.Close()
	}
}
