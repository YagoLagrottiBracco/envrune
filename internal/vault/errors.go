package vault

import (
	"errors"

	"github.com/YagoLagrottiBracco/envrune/internal/filelock"
)

var (
	ErrAlreadyExists = errors.New("vault already exists")
	ErrNotFound      = errors.New("vault not found")
	ErrCannotUnlock  = errors.New("cannot unlock vault")
	// ErrBusy means another process kept the vault lock longer than the wait
	// window. Use errors.As with *BusyError to learn which process holds it.
	ErrBusy = filelock.ErrBusy
	// ErrReplaced means the vault file on disk was re-created with a different
	// key since this process unlocked it, so its changes cannot be merged.
	ErrReplaced           = errors.New("vault was replaced on disk")
	ErrTooLarge           = errors.New("vault is too large")
	ErrNoRecovery         = errors.New("vault has no recovery key")
	ErrInvalidRecoveryKey = errors.New("invalid recovery key")
	ErrUnknownReference   = errors.New("secret reference does not exist")
	ErrNoHistory          = errors.New("secret has no earlier value")
)

// BusyError reports the process that holds the vault lock, when known.
type BusyError = filelock.BusyError
