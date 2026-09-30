// Package clipboard copies a secret to the system clipboard and clears it
// later, only if the clipboard still holds that secret.
package clipboard

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/proc"
)

var (
	ErrUnavailable = errors.New("no clipboard tool is available")
	// errNoRead means this platform can write but not read the clipboard.
	errNoRead = errors.New("clipboard cannot be read")
)

// Copy writes value to the clipboard and starts a background process that
// clears it after delay.
func Copy(value []byte, delay time.Duration) error {
	if err := write(value); err != nil {
		return err
	}
	sum := sha256.Sum256(value)
	return proc.StartDetached([]string{"__clipboard-clear", delay.String()}, []byte(hex.EncodeToString(sum[:])+"\n"))
}

// ClearMain is the entry point of the background cleaner: it waits, then
// clears the clipboard if it still holds the value whose SHA-256 arrives on
// standard input, so something copied later is left alone.
func ClearMain(args []string) int {
	if len(args) != 1 {
		return 2
	}
	delay, err := time.ParseDuration(args[0])
	if err != nil {
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 128))
	if err != nil {
		return 1
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return 1
	}
	time.Sleep(delay)
	current, err := read()
	if errors.Is(err, errNoRead) {
		return exitCode(clear())
	}
	if err != nil {
		return 1
	}
	sum := sha256.Sum256(current)
	wipe(current)
	if subtle.ConstantTimeCompare(sum[:], want) == 1 {
		return exitCode(clear())
	}
	return 0
}

func exitCode(err error) int {
	if err != nil {
		return 1
	}
	return 0
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
