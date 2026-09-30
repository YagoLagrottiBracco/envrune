package vault

import (
	"errors"
	"fmt"
)

var (
	ErrAlreadyExists = errors.New("vault already exists")
	ErrNotFound      = errors.New("vault not found")
	ErrCannotUnlock  = errors.New("cannot unlock vault")
	// ErrBusy means another process kept the vault lock longer than the wait
	// window. Use errors.As with *BusyError to learn which process holds it.
	ErrBusy = errors.New("vault is busy")
	// ErrReplaced means the vault file on disk was re-created with a different
	// key since this process unlocked it, so its changes cannot be merged.
	ErrReplaced = errors.New("vault was replaced on disk")
)

// BusyError reports the process that holds the vault lock, when known.
type BusyError struct{ PID int }

func (e *BusyError) Error() string {
	if e.PID > 0 {
		return fmt.Sprintf("vault is busy in another process (PID %d)", e.PID)
	}
	return "vault is busy in another process"
}

func (e *BusyError) Is(target error) bool { return target == ErrBusy }
