//go:build !linux

package project

type configLock struct{}

func lockConfig(string) (*configLock, error) { return &configLock{}, nil }
func (*configLock) Close()                   {}
