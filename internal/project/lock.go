package project

import (
	"errors"

	"github.com/YagoLagrottiBracco/envrune/internal/filelock"
)

func lockConfig(path string) (*filelock.Lock, error) {
	lock, err := filelock.Acquire(path)
	if errors.Is(err, filelock.ErrBusy) {
		return nil, ErrProjectBusy
	}
	return lock, err
}
