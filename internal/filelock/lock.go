// Package filelock provides short-lived, cross-process exclusive locks.
package filelock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Locks are held only while a process reads or rewrites a file, so a
// competing process waits briefly instead of failing on the first attempt.
var (
	Wait = 3 * time.Second
	poll = 25 * time.Millisecond
)

var ErrBusy = errors.New("file is locked by another process")

// BusyError reports the process that holds the lock, when known.
type BusyError struct{ PID int }

func (e *BusyError) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("locked by another process (PID %d)", e.PID)
	}
	return "locked by another process"
}

func (e *BusyError) Is(target error) bool { return target == ErrBusy }

type Lock struct{ file *os.File }

// Acquire locks path+".lock", waiting up to Wait. The lock file records the
// holder's PID so a competing process can say who holds it.
func Acquire(path string) (*Lock, error) {
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(Wait)
	for {
		held, err := tryLock(file)
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		if held {
			break
		}
		if time.Now().After(deadline) {
			pid := owner(file)
			_ = file.Close()
			return nil, &BusyError{PID: pid}
		}
		time.Sleep(poll)
	}
	if file.Truncate(0) == nil {
		_, _ = file.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	}
	return &Lock{file: file}, nil
}

// Holder reports the PID holding the lock on path without waiting, or 0
// when nobody holds it.
func Holder(path string) int {
	file, err := os.OpenFile(path+".lock", os.O_RDWR, 0600)
	if err != nil {
		return 0
	}
	defer file.Close()
	held, err := tryLock(file)
	if err != nil {
		return 0
	}
	if held {
		unlock(file)
		return 0
	}
	if pid := owner(file); pid > 0 {
		return pid
	}
	return -1
}

func owner(file *os.File) int {
	raw := make([]byte, 20)
	n, _ := file.ReadAt(raw, 0)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw[:n])))
	if err != nil {
		return 0
	}
	return pid
}

func (l *Lock) Close() {
	if l != nil {
		unlock(l.file)
		_ = l.file.Close()
	}
}
