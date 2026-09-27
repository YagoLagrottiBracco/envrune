package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/envrune/envrune/internal/app"
	"github.com/envrune/envrune/internal/paths"
)

func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		fmt.Fprintln(stderr, "usage: envrune <init|set|list>")
		return 2
	}
	if args[0] == "set" && len(args) != 2 {
		fmt.Fprintln(stderr, "usage: envrune set <secret-reference>")
		return 2
	}
	if (args[0] == "init" || args[0] == "list") && len(args) != 1 {
		fmt.Fprintln(stderr, "invalid command arguments")
		return 2
	}
	if args[0] != "init" && args[0] != "set" && args[0] != "list" {
		fmt.Fprintln(stderr, "unknown command")
		return 2
	}
	p := SecretPrompt{Output: stderr}
	password, err := p.Read("Master password")
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
	s := app.VaultService{}
	if args[0] == "init" {
		confirmation, e := p.Read("Confirm master password")
		if e != nil {
			fmt.Fprintln(stderr, "secure interactive input is required")
			return 1
		}
		defer wipe(confirmation)
		err = s.Init(path, password, confirmation)
	} else if args[0] == "set" {
		value, e := p.Read("Secret value")
		if e != nil {
			fmt.Fprintln(stderr, "secure interactive input is required")
			return 1
		}
		defer wipe(value)
		err = s.Set(path, password, args[1], value)
	} else {
		var refs []string
		refs, err = s.List(path, password)
		for _, r := range refs {
			fmt.Fprintln(stdout, r)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "command failed")
		return 1
	}
	return 0
}
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
