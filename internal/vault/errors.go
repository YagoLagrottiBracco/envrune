package vault

import "errors"

var (
	ErrAlreadyExists = errors.New("vault already exists")
	ErrNotFound      = errors.New("vault not found")
	ErrCannotUnlock  = errors.New("cannot unlock vault")
)
