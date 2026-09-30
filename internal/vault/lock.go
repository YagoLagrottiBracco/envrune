package vault

import "github.com/YagoLagrottiBracco/envrune/internal/filelock"

func acquireLock(path string) (*filelock.Lock, error) { return filelock.Acquire(path) }

// LockHolder reports the PID holding the vault lock right now: 0 when it is
// free, -1 when it is held by an unknown process.
func LockHolder(path string) int { return filelock.Holder(path) }
