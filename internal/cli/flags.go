package cli

import (
	"errors"
	"strings"
)

var errUsage = errors.New("invalid command arguments")

// args is a parsed command line: positional arguments, --name value
// options, boolean --flags, and everything after "--".
type args struct {
	positional []string
	options    map[string]string
	flags      map[string]bool
	rest       []string
	hasRest    bool
}

// parseArgs accepts the listed options (which take a value) and flags. With
// stopAtCommand, the first positional argument and everything after it go to
// rest, so `run npm --version` keeps --version for npm.
func parseArgs(raw []string, options, flags []string, stopAtCommand bool) (args, error) {
	out := args{options: map[string]string{}, flags: map[string]bool{}}
	isOption := map[string]bool{}
	for _, name := range options {
		isOption[name] = true
	}
	isFlag := map[string]bool{}
	for _, name := range flags {
		isFlag[name] = true
	}
	for i := 0; i < len(raw); i++ {
		arg := raw[i]
		switch {
		case arg == "--":
			out.rest, out.hasRest = raw[i+1:], true
			return out, nil
		case strings.HasPrefix(arg, "--") && len(arg) > 2:
			name, value, hasValue := strings.Cut(arg[2:], "=")
			switch {
			case isOption[name] && hasValue:
				out.options[name] = value
			case isOption[name] && i+1 < len(raw):
				out.options[name] = raw[i+1]
				i++
			case isFlag[name] && !hasValue:
				out.flags[name] = true
			default:
				return args{}, errUsage
			}
		case stopAtCommand:
			out.rest, out.hasRest = raw[i:], true
			return out, nil
		default:
			out.positional = append(out.positional, arg)
		}
	}
	return out, nil
}
