// Mkvault creates a vault for tests that cannot type a password into
// `envrune init`: mkvault <vault path> <password> [reference=value...].
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: mkvault <vault path> <password> [reference=value...]")
		os.Exit(2)
	}
	path, password := os.Args[1], []byte(os.Args[2])
	if _, err := (app.VaultService{}).Init(path, password, password); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	session, err := app.OpenSession(path, password)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer session.Close()
	for _, pair := range os.Args[3:] {
		ref, value, _ := strings.Cut(pair, "=")
		if err := session.Set(ref, []byte(value)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
