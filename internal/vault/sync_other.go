//go:build !linux

package vault

func syncParent(string) error { return nil }
