//go:build !linux

package vault

type vaultLock struct{}

func acquireLock(string) (*vaultLock, error) { return &vaultLock{}, nil }
func (*vaultLock) Close()                    {}
