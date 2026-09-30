//go:build !linux && !darwin && !windows

package cli

func discardPendingInput(int) bool { return false }
