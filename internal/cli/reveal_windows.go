//go:build windows

package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableEscapes turns on escape sequences for a Windows console, which
// does not interpret them unless asked. It fails on consoles too old to.
func enableEscapes(file *os.File) (func(), bool) {
	handle := windows.Handle(file.Fd())
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		return nil, false
	}
	if windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT) != nil {
		return nil, false
	}
	return func() { _ = windows.SetConsoleMode(handle, mode) }, true
}
