// Envrune is a local-first encrypted environment-variable manager.
package main

import (
	"os"

	"github.com/YagoLagrottiBracco/envrune/internal/cli"
)

// The helper processes Envrune starts from its own binary (the agent, the
// clipboard cleaner, and the Linux exec shim) are dispatched from the init
// functions of their packages, before main runs.
func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
