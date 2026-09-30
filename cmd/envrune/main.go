// Envrune is a local-first encrypted environment-variable manager.
package main

import (
	"os"

	"github.com/YagoLagrottiBracco/envrune/internal/agent"
	"github.com/YagoLagrottiBracco/envrune/internal/cli"
	"github.com/YagoLagrottiBracco/envrune/internal/clipboard"
	"github.com/YagoLagrottiBracco/envrune/internal/runner"
)

func main() {
	if len(os.Args) > 1 {
		// Internal entry points for helper processes that Envrune starts.
		switch os.Args[1] {
		case "__envrune_exec":
			os.Exit(runner.ChildExec(os.Args[2:]))
		case "__agent":
			os.Exit(agent.Main(os.Args[2:]))
		case "__clipboard-clear":
			os.Exit(clipboard.ClearMain(os.Args[2:]))
		}
	}
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
