package agent

import (
	"bufio"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/proc"
)

// Start launches a detached agent that holds key for ttl, then waits until it
// answers.
func Start(socketPath string, key []byte, ttl time.Duration) error {
	input := []byte(hex.EncodeToString(key) + "\n")
	defer wipe(input)
	if err := proc.StartDetached([]string{"__agent", socketPath, ttl.String()}, input); err != nil {
		return err
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, err := Status(socketPath); err == nil {
			return nil
		}
	}
	return errors.New("the agent did not start")
}

// Main is the entry point of the detached agent process: args are the socket
// path and the time to live; the hex key arrives on standard input.
func Main(args []string) int {
	if len(args) != 2 {
		return 2
	}
	ttl, err := time.ParseDuration(args[1])
	if err != nil || ttl <= 0 {
		return 2
	}
	hardenProcess()
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return 1
	}
	key, err := hex.DecodeString(strings.TrimSpace(line))
	if err != nil || len(key) != 32 {
		return 1
	}
	if err := Serve(args[0], key, ttl); err != nil {
		return 1
	}
	return 0
}
