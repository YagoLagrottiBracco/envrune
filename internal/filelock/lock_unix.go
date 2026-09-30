//go:build unix

package filelock

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func tryLock(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK):
		return false, nil
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.ENOLCK), errors.Is(err, unix.EINVAL):
		// Some file systems, such as network or Windows drives mounted in
		// WSL, cannot lock. Writes stay atomic; only serialization is lost.
		return true, nil
	}
	return false, err
}

func unlock(file *os.File) { _ = unix.Flock(int(file.Fd()), unix.LOCK_UN) }
