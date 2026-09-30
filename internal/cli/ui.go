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

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/ui"
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

func executeSessionUI(session *app.Session, args []string, stdout, stderr io.Writer) int {
	port, browser, err := uiArguments(args)
	if err != nil {
		fmt.Fprintln(stderr, "usage: envrune ui [--port <port>] [--no-browser]")
		return 2
	}
	if session == nil {
		NewPresenter(stdout, stderr, os.Getenv).Error("Local interface is unavailable.")
		return 1
	}
	return serveUI(port, browser, session, stdout, stderr)
}

func serveUI(port int, browser bool, source ui.MetadataSource, stdout, stderr io.Writer) int {
	status := NewPresenter(stdout, stderr, os.Getenv)
	server, err := ui.New(port, source)
	if err != nil {
		status.Error("Local interface is unavailable.")
		return 1
	}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	address := server.URL()
	status.Info("Open this one-time local link within 5 minutes:")
	fmt.Fprintln(stdout, address)
	status.Info("Press Ctrl+C or use Lock & exit to close the session.")
	if browser {
		openBrowser(address)
	}
	if err := server.Serve(ctx); err != nil {
		status.Error("Local interface stopped.")
		return 1
	}
	return 0
}

func openBrowser(address string) {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		command = exec.Command("xdg-open", address)
	case "darwin":
		command = exec.Command("open", address)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", address)
	default:
		return
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if command.Start() == nil {
		go func() { _ = command.Wait() }()
	}
}
