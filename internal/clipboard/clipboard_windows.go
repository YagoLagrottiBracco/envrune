//go:build windows

package clipboard

import (
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                      = windows.NewLazySystemDLL("user32.dll")
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard           = user32.NewProc("OpenClipboard")
	procCloseClipboard          = user32.NewProc("CloseClipboard")
	procEmptyClipboard          = user32.NewProc("EmptyClipboard")
	procSetClipboardData        = user32.NewProc("SetClipboardData")
	procGetClipboardData        = user32.NewProc("GetClipboardData")
	procRegisterClipboardFormat = user32.NewProc("RegisterClipboardFormatW")
	procGlobalAlloc             = kernel32.NewProc("GlobalAlloc")
	procGlobalLock              = kernel32.NewProc("GlobalLock")
	procGlobalUnlock            = kernel32.NewProc("GlobalUnlock")
	procGlobalFree              = kernel32.NewProc("GlobalFree")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

func open() error {
	var err error
	for i := 0; i < 20; i++ {
		ok, _, callErr := procOpenClipboard.Call(0)
		if ok != 0 {
			return nil
		}
		err = callErr
		time.Sleep(25 * time.Millisecond)
	}
	return err
}

func closeClipboard() { _, _, _ = procCloseClipboard.Call() }

// pointer turns a Win32 memory handle into a Go pointer without a direct
// uintptr conversion.
func pointer(address uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&address)) }

func setData(format uintptr, data []byte) error {
	size := max(len(data), 1)
	handle, _, err := procGlobalAlloc.Call(gmemMoveable, uintptr(size))
	if handle == 0 {
		return err
	}
	address, _, err := procGlobalLock.Call(handle)
	if address == 0 {
		_, _, _ = procGlobalFree.Call(handle)
		return err
	}
	copy(unsafe.Slice((*byte)(pointer(address)), size), data)
	_, _, _ = procGlobalUnlock.Call(handle)
	if ok, _, err := procSetClipboardData.Call(format, handle); ok == 0 {
		_, _, _ = procGlobalFree.Call(handle)
		return err
	}
	return nil
}

func registeredFormat(name string) uintptr {
	text, _ := windows.UTF16PtrFromString(name)
	format, _, _ := procRegisterClipboardFormat.Call(uintptr(unsafe.Pointer(text)))
	return format
}

func write(value []byte) error {
	if err := open(); err != nil {
		return err
	}
	defer closeClipboard()
	if ok, _, err := procEmptyClipboard.Call(); ok == 0 {
		return err
	}
	units := utf16.Encode([]rune(string(value) + "\x00"))
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&units[0])), len(units)*2)
	defer wipe(raw)
	if err := setData(cfUnicodeText, raw); err != nil {
		return err
	}
	// Keep the secret out of clipboard history, cloud sync, and monitors.
	zero := []byte{0, 0, 0, 0}
	if format := registeredFormat("ExcludeClipboardContentFromMonitorProcessing"); format != 0 {
		_ = setData(format, zero)
	}
	if format := registeredFormat("CanIncludeInClipboardHistory"); format != 0 {
		_ = setData(format, zero)
	}
	if format := registeredFormat("CanUploadToCloudClipboard"); format != 0 {
		_ = setData(format, zero)
	}
	return nil
}

func read() ([]byte, error) {
	if err := open(); err != nil {
		return nil, err
	}
	defer closeClipboard()
	handle, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return nil, nil
	}
	address, _, err := procGlobalLock.Call(handle)
	if address == 0 {
		return nil, err
	}
	defer procGlobalUnlock.Call(handle)
	var units []uint16
	for p := (*uint16)(pointer(address)); *p != 0; p = (*uint16)(unsafe.Add(unsafe.Pointer(p), 2)) {
		units = append(units, *p)
	}
	return []byte(string(utf16.Decode(units))), nil
}

func clear() error {
	if err := open(); err != nil {
		return err
	}
	defer closeClipboard()
	if ok, _, err := procEmptyClipboard.Call(); ok == 0 {
		return err
	}
	return nil
}
