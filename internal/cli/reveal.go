package cli

import (
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/term"

	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

// A recovery key printed among a command's output stays in the terminal's
// scrollback, and gets copied along with the rest when someone pastes that
// output into a chat or an issue. On a terminal the key is therefore shown
// on the alternate screen, which keeps no history, and leaves it once the
// user types one of its groups back: proof that it was written down, not
// scrolled past.

const (
	enterAlternateScreen = "\x1b[?1049h\x1b[2J\x1b[H"
	leaveAlternateScreen = "\x1b[?1049l"
)

// keyReveal is how a recovery key is shown. The zero value detects the
// terminal; tests set the fields.
type keyReveal struct {
	// Screen prepares out for the alternate screen and reports whether it
	// is a terminal that has one; restore undoes what it changed.
	Screen   func(out io.Writer) (restore func(), ok bool)
	ReadLine func() (string, error)
	// Group picks which of n groups to ask for, from 0.
	Group func(n int) int
}

// showRecoveryKey shows key once. use says what the key is for, and again
// names the command that makes a new one if this one was not written down.
func showRecoveryKey(out io.Writer, status Presenter, key []byte, use, again string) {
	keyReveal{}.show(out, status, key, use, again)
}

func (r keyReveal) show(out io.Writer, status Presenter, key []byte, use, again string) {
	screen := r.Screen
	if screen == nil {
		screen = alternateScreen
	}
	restore, ok := screen(out)
	if !ok {
		// Redirected output is a script's or a test's: it gets the key as text.
		status.Warn("Write down this recovery key and keep it offline. It is shown only once.")
		fmt.Fprintf(out, "\n    %s\n\n", vault.FormatRecoveryKey(key))
		status.Info(use)
		return
	}
	readLine, group := r.ReadLine, r.Group
	if readLine == nil {
		readLine = readChoiceLine
	}
	if group == nil {
		group = rand.IntN
	}
	formatted := vault.FormatRecoveryKey(key)
	groups := strings.Split(formatted, "-")
	ask := group(len(groups))

	// Ctrl+C must not leave the terminal on the alternate screen.
	interrupted := make(chan os.Signal, 1)
	signal.Notify(interrupted, os.Interrupt)
	done := make(chan struct{})
	go func() {
		select {
		case <-interrupted:
			fmt.Fprint(out, leaveAlternateScreen)
			restore()
			os.Exit(130)
		case <-done:
		}
	}()

	fmt.Fprint(out, enterAlternateScreen)
	fmt.Fprintf(out, "\n  Write down this recovery key and keep it offline.\n\n      %s\n\n", formatted)
	fmt.Fprintf(out, "  It is shown only once, and leaves the screen when you confirm it.\n  %s\n\n", use)
	confirmed := false
	for prompt := fmt.Sprintf("  Type group %d of the key, counting from the left, to confirm you wrote it down: ", ask+1); ; {
		fmt.Fprint(out, prompt)
		line, err := readLine()
		if err != nil {
			break
		}
		if strings.EqualFold(strings.TrimSpace(line), groups[ask]) {
			confirmed = true
			break
		}
		prompt = fmt.Sprintf("  That is not group %d. Check what you wrote down and type it again: ", ask+1)
	}
	fmt.Fprint(out, leaveAlternateScreen)
	signal.Stop(interrupted)
	close(done)
	restore()

	if confirmed {
		status.Success("The recovery key is written down, and no longer on this screen.")
		status.Info(use)
		return
	}
	status.Warn("The recovery key was not confirmed. If you did not write it down, run `" + again + "` for a new one.")
}

// alternateScreen reports whether out and the input are a terminal with an
// alternate screen, and prepares out for it.
func alternateScreen(out io.Writer) (func(), bool) {
	file, ok := out.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) || os.Getenv("TERM") == "dumb" {
		return nil, false
	}
	return enableEscapes(file)
}
