//go:build windows

package cli

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var procPeekConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekConsoleInputW")

// inputRecord mirrors INPUT_RECORD holding a KEY_EVENT_RECORD.
type inputRecord struct {
	EventType       uint16
	_               uint16
	KeyDown         int32
	RepeatCount     uint16
	VirtualKeyCode  uint16
	VirtualScanCode uint16
	Char            uint16
	ControlKeyState uint32
}

const keyEvent = 0x0001

// discardPendingInput flushes typed-ahead characters left in the console
// after a secret prompt, such as the extra lines of a multi-line paste, and
// reports whether there were any. Key releases alone do not count.
func discardPendingInput(fd int) bool {
	handle := windows.Handle(fd)
	var count uint32
	if windows.GetNumberOfConsoleInputEvents(handle, &count) != nil || count == 0 {
		return false
	}
	records := make([]inputRecord, min(count, 512))
	var read uint32
	ok, _, _ := procPeekConsoleInput.Call(uintptr(handle), uintptr(unsafe.Pointer(&records[0])), uintptr(len(records)), uintptr(unsafe.Pointer(&read)))
	if ok == 0 {
		return false
	}
	pending := false
	for _, record := range records[:read] {
		if record.EventType == keyEvent && record.KeyDown != 0 && record.Char != 0 {
			pending = true
			break
		}
	}
	if pending {
		_ = windows.FlushConsoleInputBuffer(handle)
	}
	return pending
}
