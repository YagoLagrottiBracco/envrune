package runner

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// drainTimeout bounds how long Wait reads output after the child exits.
const drainTimeout = 2 * time.Second

// pseudoConsoleInheritCursor is PSEUDOCONSOLE_INHERIT_CURSOR.
const pseudoConsoleInheritCursor = 0x1

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procCreatePseudoConsole = kernel32.NewProc("CreatePseudoConsole")
	procWriteConsoleInput   = kernel32.NewProc("WriteConsoleInputW")
	procPeekConsoleInput    = kernel32.NewProc("PeekConsoleInputW")
	procReadConsoleInput    = kernel32.NewProc("ReadConsoleInputW")
)

// terminalAvailable reports whether this Windows has ConPTY (1809 or later).
func terminalAvailable() bool { return procCreatePseudoConsole.Find() == nil }

// console is the parent's side of a child's pseudo console.
type console struct {
	pc      windows.Handle
	input   windows.Handle // writes reach the child as typed keys
	output  chan struct{}  // closed when the child's output is fully copied
	closing sync.Once
	restore func()
}

func startTerminal(name, path string, spec Spec, env []string) (*Process, error) {
	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, &StartError{Name: name, Err: err}
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		closeHandles(inRead, inWrite)
		return nil, &StartError{Name: name, Err: err}
	}
	// With a real console behind it, ConPTY starts at the current cursor
	// position instead of clearing the screen. It asks the terminal where the
	// cursor is, so only do this when a terminal is there to answer.
	var flags uint32
	var mode uint32
	if spec.Stdin == io.Reader(os.Stdin) && windows.GetConsoleMode(windows.Handle(os.Stdin.Fd()), &mode) == nil {
		flags = pseudoConsoleInheritCursor
	}
	var pc windows.Handle
	err := windows.CreatePseudoConsole(consoleSize(), inRead, outWrite, flags, &pc)
	closeHandles(inRead, outWrite) // the pseudo console holds its own copies
	if err != nil {
		closeHandles(inWrite, outRead)
		return nil, &StartError{Name: name, Err: err}
	}
	process, err := createAttached(path, spec, env, pc)
	if err != nil {
		windows.ClosePseudoConsole(pc)
		closeHandles(inWrite, outRead)
		return nil, &StartError{Name: name, Err: err}
	}
	c := &console{pc: pc, input: inWrite, output: make(chan struct{}), restore: func() {}}
	go func() {
		defer close(c.output)
		out := os.NewFile(uintptr(outRead), "conpty-output")
		defer out.Close()
		_, _ = io.Copy(spec.Stdout, out)
	}()
	if spec.Stdin == io.Reader(os.Stdin) {
		c.restore = c.attachInput()
	} else if spec.Stdin != nil {
		go func() { _, _ = io.Copy(handleWriter(inWrite), spec.Stdin) }()
	}
	p := &Process{process: process, name: name, group: spec.Group, console: c}
	p.tree = track(process)
	return p, nil
}

// createAttached starts path with the pseudo console as its terminal.
func createAttached(path string, spec Spec, env []string, pc windows.Handle) (*os.Process, error) {
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return nil, err
	}
	defer attrs.Delete()
	// The attribute value is the console handle itself, not a pointer to it.
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, *(*unsafe.Pointer)(unsafe.Pointer(&pc)), unsafe.Sizeof(pc)); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	// Empty standard handles make the child use the pseudo console even when
	// this process's own streams are redirected.
	si.Flags = windows.STARTF_USESTDHANDLES
	app, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	line, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(spec.Command))
	if err != nil {
		return nil, err
	}
	var dir *uint16
	if spec.Dir != "" {
		if dir, err = windows.UTF16PtrFromString(spec.Dir); err != nil {
			return nil, err
		}
	}
	block := environmentBlock(env)
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)
	if spec.Group {
		flags |= windows.CREATE_NEW_PROCESS_GROUP
	}
	var info windows.ProcessInformation
	if err := windows.CreateProcess(app, line, nil, nil, false, flags, &block[0], dir, &si.StartupInfo, &info); err != nil {
		return nil, err
	}
	defer closeHandles(info.Thread, info.Process)
	// The handle kept open until here stops the PID from being reused.
	return os.FindProcess(int(info.ProcessId))
}

// environmentBlock encodes env as the double-NUL-terminated UTF-16 block
// CreateProcess expects.
func environmentBlock(env []string) []uint16 {
	var block []uint16
	for _, entry := range env {
		block = append(block, utf16.Encode([]rune(entry))...)
		block = append(block, 0)
	}
	return append(block, 0)
}

func consoleSize() windows.Coord {
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(windows.Handle(os.Stdout.Fd()), &info) != nil {
		return windows.Coord{X: 120, Y: 30}
	}
	return windows.Coord{X: info.Window.Right - info.Window.Left + 1, Y: info.Window.Bottom - info.Window.Top + 1}
}

// attachInput puts this process's console in virtual-terminal mode, so
// keys reach the child as the escape sequences ConPTY expects and its
// output is interpreted, forwards what is typed, and follows resizes. The
// returned function undoes all of it and stops reading, so nothing typed
// after the child exits is taken from the next reader.
func (c *console) attachInput() func() {
	in, out := windows.Handle(os.Stdin.Fd()), windows.Handle(os.Stdout.Fd())
	var inMode, outMode uint32
	restoreOut := func() {}
	if windows.GetConsoleMode(out, &outMode) == nil {
		_ = windows.SetConsoleMode(out, outMode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT)
		restoreOut = func() { _ = windows.SetConsoleMode(out, outMode) }
	}
	if windows.GetConsoleMode(in, &inMode) != nil {
		return restoreOut
	}
	_ = windows.SetConsoleMode(in, windows.ENABLE_VIRTUAL_TERMINAL_INPUT)
	stopRead := forwardConsole(in, c.input)
	stopResize := c.followResize()
	return func() {
		stopResize()
		stopRead()
		// ConPTY turns on win32-input-mode and focus reports in the terminal
		// and leaves them on when it closes, so the next line typed at the
		// shell would arrive encoded. Turn them off while this console still
		// interprets escape sequences.
		_, _ = os.Stdout.WriteString("\x1b[?9001l\x1b[?1004l\x1b[?25h")
		_ = windows.SetConsoleMode(in, inMode)
		restoreOut()
	}
}

// forwardConsole copies typed input to the child until the returned
// function is called. A blocked console read cannot be cancelled cleanly:
// CancelSynchronousIo returns control, but the console keeps the read queued
// and gives it the next keys typed, which the shell then never sees. So the
// stop function ends the read the ordinary way, by typing a marker key into
// the console, and removes the marker if the reader had already stopped.
func forwardConsole(in, dst windows.Handle) func() {
	done := make(chan struct{})
	var stopping atomic.Bool
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		for !stopping.Load() {
			var n, written uint32
			if windows.ReadFile(in, buf, &n, nil) != nil || stopping.Load() {
				return
			}
			if n > 0 && windows.WriteFile(dst, buf[:n], &written, nil) != nil {
				return
			}
		}
	}()
	return func() {
		stopping.Store(true)
		for attempt := 0; attempt < 10; attempt++ {
			if writeMarker(in) != nil {
				break
			}
			select {
			case <-done:
				attempt = 10
			case <-time.After(100 * time.Millisecond):
			}
		}
		removeMarkers(in)
	}
}

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

const (
	keyEvent = 0x0001
	// markerChar is a private-use character no keyboard produces.
	markerChar = 0xE000
)

var marker = inputRecord{EventType: keyEvent, KeyDown: 1, RepeatCount: 1, Char: markerChar}

func (r inputRecord) isMarker() bool {
	return r.EventType == keyEvent && r.Char == markerChar && r.VirtualKeyCode == 0 && r.VirtualScanCode == 0
}

func writeMarker(in windows.Handle) error {
	var written uint32
	record := marker
	if ok, _, err := procWriteConsoleInput.Call(uintptr(in), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&written))); ok == 0 {
		return err
	}
	return nil
}

// removeMarkers takes every marker out of the console input, keeping what
// the user typed in order.
func removeMarkers(in windows.Handle) {
	var count uint32
	if windows.GetNumberOfConsoleInputEvents(in, &count) != nil || count == 0 {
		return
	}
	records := make([]inputRecord, count)
	var read uint32
	if ok, _, _ := procPeekConsoleInput.Call(uintptr(in), uintptr(unsafe.Pointer(&records[0])), uintptr(count), uintptr(unsafe.Pointer(&read))); ok == 0 {
		return
	}
	found := false
	for _, record := range records[:read] {
		found = found || record.isMarker()
	}
	if !found {
		return
	}
	if ok, _, _ := procReadConsoleInput.Call(uintptr(in), uintptr(unsafe.Pointer(&records[0])), uintptr(read), uintptr(unsafe.Pointer(&read))); ok == 0 {
		return
	}
	kept := records[:0]
	for _, record := range records[:read] {
		if !record.isMarker() {
			kept = append(kept, record)
		}
	}
	if len(kept) > 0 {
		var written uint32
		_, _, _ = procWriteConsoleInput.Call(uintptr(in), uintptr(unsafe.Pointer(&kept[0])), uintptr(len(kept)), uintptr(unsafe.Pointer(&written)))
	}
}

// followResize resizes the pseudo console when this console's window
// changes. Console windows send no signal a program can wait on without
// reading input, so it checks four times a second.
func (c *console) followResize() func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		last := consoleSize()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				if size := consoleSize(); size != last {
					last = size
					_ = windows.ResizePseudoConsole(c.pc, size)
				}
			}
		}
	}()
	return func() { close(stop); <-done }
}

// finish runs after the child exits. Closing the pseudo console ends its
// output stream once the last output is read.
func (c *console) finish() {
	defer c.restore()
	c.closing.Do(func() {
		closed := make(chan struct{})
		go func() {
			windows.ClosePseudoConsole(c.pc)
			close(closed)
		}()
		select {
		case <-c.output:
		case <-time.After(drainTimeout):
		}
		select {
		case <-closed:
		case <-time.After(drainTimeout):
		}
		_ = windows.CloseHandle(c.input)
	})
}

// handleWriter writes to a pipe handle without taking ownership of it.
type handleWriter windows.Handle

func (h handleWriter) Write(p []byte) (int, error) {
	var n uint32
	err := windows.WriteFile(windows.Handle(h), p, &n, nil)
	return int(n), err
}

func closeHandles(handles ...windows.Handle) {
	for _, h := range handles {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
	}
}
