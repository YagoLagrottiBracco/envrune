//go:build !linux

package project

func syncParent(string) error { return nil }
