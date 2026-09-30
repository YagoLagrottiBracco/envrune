//go:build linux || darwin

package runner

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// drainTimeout bounds how long Wait reads output after the child exits. A
// process the child left running can keep the terminal open forever.
const drainTimeout = time.Second

func terminalAvailable() bool { return true }

// console is the parent's side of a child's pseudo-terminal.
type console struct {
	master  *os.File
	output  chan struct{} // closed when the child's output is fully copied
	restore func()        // gives this process's terminal back
}

func startTerminal(name, path string, spec Spec, env []string) (*Process, error) {
	cmd, err := childCommand(path, spec.Command)
	if err != nil {
		return nil, &StartError{Name: name, Err: err}
	}
	cmd.Dir, cmd.Env = spec.Dir, env
	master, tty, err := pty.Open()
	if err != nil {
		return nil, &StartError{Name: name, Err: err}
	}
	if term.IsTerminal(int(os.Stdout.Fd())) {
		_ = pty.InheritSize(os.Stdout, master)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	// A new session whose controlling terminal is the pty; the child leads
	// its process group, so Stop reaches everything it starts.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	err = cmd.Start()
	_ = tty.Close()
	if err != nil {
		_ = master.Close()
		return nil, &StartError{Name: name, Err: err}
	}
	c := &console{master: master, output: make(chan struct{}), restore: func() {}}
	go func() {
		defer close(c.output)
		_, _ = io.Copy(spec.Stdout, master) // ends with EIO once the terminal closes
	}()
	if spec.Stdin == io.Reader(os.Stdin) {
		c.restore = attachInput(master)
	} else if spec.Stdin != nil {
		go func() { _, _ = io.Copy(master, spec.Stdin) }()
	}
	return &Process{cmd: cmd, process: cmd.Process, name: name, group: true, console: c}, nil
}

// attachInput switches this process's terminal to raw mode, forwards what
// is typed to the child, and follows window resizes. The returned function
// undoes all of it and stops reading, so nothing typed after the child
// exits is taken from the next reader, such as `envrune shell`.
func attachInput(master *os.File) func() {
	in := int(os.Stdin.Fd())
	if !term.IsTerminal(in) {
		return func() {}
	}
	state, err := term.MakeRaw(in)
	if err != nil {
		return func() {}
	}
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			_ = pty.InheritSize(os.Stdin, master)
		}
	}()
	stopRead := forwardInput(in, master)
	return func() {
		stopRead()
		signal.Stop(winch)
		close(winch)
		_ = term.Restore(in, state)
	}
}

// forwardInput copies from fd to dst until the returned function is called.
// It waits with select on fd and on a pipe, so it can stop without a read
// in flight.
func forwardInput(fd int, dst io.Writer) func() {
	cancelR, cancelW, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		cancel := int(cancelR.Fd())
		buf := make([]byte, 1024)
		for {
			var set unix.FdSet
			set.Set(fd)
			set.Set(cancel)
			if _, err := unix.Select(max(fd, cancel)+1, &set, nil, nil, nil); err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return
			}
			if set.IsSet(cancel) {
				return
			}
			n, err := unix.Read(fd, buf)
			if n > 0 {
				_, _ = dst.Write(buf[:n])
			}
			if n == 0 || (err != nil && !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EAGAIN)) {
				return
			}
		}
	}()
	return func() {
		_, _ = cancelW.Write([]byte{0})
		<-done
		_ = cancelR.Close()
		_ = cancelW.Close()
	}
}

// finish runs after the child exits: it lets the last output through, then
// closes the terminal and gives this process's terminal back.
func (c *console) finish() {
	select {
	case <-c.output:
	case <-time.After(drainTimeout):
	}
	_ = c.master.Close()
	<-c.output
	c.restore()
}
