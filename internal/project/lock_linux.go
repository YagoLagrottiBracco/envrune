//go:build linux

package project

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

type configLock struct{ file *os.File }

func lockConfig(path string) (*configLock, error) {
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrProjectBusy
		}
		return nil, err
	}
	return &configLock{file}, nil
}
func (l *configLock) Close() {
	if l != nil {
		_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
		_ = l.file.Close()
	}
}
