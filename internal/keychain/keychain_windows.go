//go:build windows

package keychain

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredWrite  = advapi32.NewProc("CredWriteW")
	procCredRead   = advapi32.NewProc("CredReadW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

// credential mirrors CREDENTIALW.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func target(account string) (*uint16, error) {
	return windows.UTF16PtrFromString(service + ":" + account)
}

func set(account string, secret []byte) error {
	name, err := target(account)
	if err != nil {
		return err
	}
	user, _ := windows.UTF16PtrFromString(account)
	comment, _ := windows.UTF16PtrFromString("EnvRune vault key")
	cred := credential{
		Type:               credTypeGeneric,
		TargetName:         name,
		Comment:            comment,
		CredentialBlobSize: uint32(len(secret)),
		CredentialBlob:     &secret[0],
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}
	if ok, _, callErr := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0); ok == 0 {
		return callErr
	}
	return nil
}

func get(account string) ([]byte, error) {
	name, err := target(account)
	if err != nil {
		return nil, err
	}
	var pcred *credential
	ok, _, callErr := procCredRead.Call(uintptr(unsafe.Pointer(name)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&pcred)))
	if ok == 0 {
		if errors.Is(callErr, windows.ERROR_NOT_FOUND) {
			return nil, ErrNotFound
		}
		return nil, callErr
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(pcred)))
	blob := unsafe.Slice(pcred.CredentialBlob, pcred.CredentialBlobSize)
	out := append([]byte(nil), blob...)
	wipe(blob)
	return out, nil
}

func remove(account string) error {
	name, err := target(account)
	if err != nil {
		return err
	}
	if ok, _, callErr := procCredDelete.Call(uintptr(unsafe.Pointer(name)), credTypeGeneric, 0); ok == 0 && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		return callErr
	}
	return nil
}
