package vault

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Locks are held only while a process reads or rewrites the vault file, so a
// competing process waits briefly instead of failing on the first attempt.
var (
	lockWait = 3 * time.Second
	lockPoll = 25 * time.Millisecond
)

type vaultLock struct{ file *os.File }

func acquireLock(path string) (*vaultLock, error) {
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
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
			pid := lockOwner(file)
			_ = file.Close()
			return nil, &BusyError{PID: pid}
		}
		time.Sleep(lockPoll)
	}
	if file.Truncate(0) == nil {
		_, _ = file.WriteAt([]byte(strconv.Itoa(os.Getpid())), 0)
	}
	return &vaultLock{file: file}, nil
}

func lockOwner(file *os.File) int {
	raw := make([]byte, 20)
	n, _ := file.ReadAt(raw, 0)
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw[:n])))
	if err != nil {
		return 0
	}
	return pid
}

func (l *vaultLock) Close() {
	if l != nil {
		unlock(l.file)
		_ = l.file.Close()
	}
}
