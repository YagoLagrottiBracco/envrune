// Envrune is a local-first encrypted environment-variable manager.
package main

import (
	"github.com/envrune/envrune/internal/cli"
	"github.com/envrune/envrune/internal/runner"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__envrune_exec" { os.Exit(runner.ChildExec(os.Args[2:])) }
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
