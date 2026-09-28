package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"github.com/envrune/envrune/internal/app"
	"github.com/envrune/envrune/internal/paths"
	"github.com/envrune/envrune/internal/ui"
)

func uiArguments(args []string) (int, bool, error) {
	port, browser, portSeen, browserSeen := 0, true, false, false
	for len(args) > 0 {
		switch args[0] {
		case "--port":
			if portSeen || len(args) < 2 {
				return 0, false, errors.New("invalid UI arguments")
			}
			value, err := strconv.Atoi(args[1])
			if err != nil || value < 0 || value > 65535 {
				return 0, false, errors.New("invalid UI arguments")
			}
			port, portSeen, args = value, true, args[2:]
		case "--no-browser":
			if browserSeen {
				return 0, false, errors.New("invalid UI arguments")
			}
			browser, browserSeen, args = false, true, args[1:]
		default:
			return 0, false, errors.New("invalid UI arguments")
		}
	}
	return port, browser, nil
}

func executeUI(args []string, stdout, stderr io.Writer) int {
	port, browser, err := uiArguments(args)
	if err != nil {
		fmt.Fprintln(stderr, "usage: envrune ui [--port <port>] [--no-browser]")
		return 2
	}
	password, err := (SecretPrompt{Output: stderr}).Read("Master password")
	if err != nil {
		fmt.Fprintln(stderr, "secure interactive input is required")
		return 1
	}
	defer wipe(password)
	path, err := paths.VaultPath(os.Getenv, os.UserHomeDir)
	if err != nil {
		fmt.Fprintln(stderr, "vault path unavailable")
		return 1
	}
	dashboard, err := app.OpenDashboard(path, password)
	wipe(password)
	if err != nil {
		fmt.Fprintln(stderr, "command failed")
		return 1
	}
	defer dashboard.Close()
	server, err := ui.New(port, dashboard)
	if err != nil {
		fmt.Fprintln(stderr, "local interface unavailable")
		return 1
	}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	address := server.URL()
	fmt.Fprintln(stdout, "Open this one-time local link within 5 minutes:")
	fmt.Fprintln(stdout, address)
	fmt.Fprintln(stdout, "Press Ctrl+C or use Lock & exit to close the session.")
	if browser {
		openBrowser(address)
	}
	if err := server.Serve(ctx); err != nil {
		fmt.Fprintln(stderr, "local interface stopped")
		return 1
	}
	return 0
}

func openBrowser(address string) {
	if runtime.GOOS != "linux" {
		return
	}
	command := exec.Command("xdg-open", address)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Start() == nil {
		go func() { _ = command.Wait() }()
	}
}
