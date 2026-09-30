//go:build !linux && !darwin && !windows

package runner

// Other systems get pipes instead of a pseudo-terminal.
func terminalAvailable() bool { return false }

type console struct{}

func startTerminal(string, string, Spec, []string) (*Process, error) { panic("unreachable") }

func (*console) finish() {}
