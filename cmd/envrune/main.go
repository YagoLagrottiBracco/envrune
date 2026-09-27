// Envrune is a local-first encrypted environment-variable manager.
package main

import (
	"github.com/envrune/envrune/internal/cli"
	"os"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
