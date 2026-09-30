//go:build !windows

package clipboard

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
)

type tool struct {
	copy  []string
	paste []string // empty when the tool cannot read
	clear []string // empty means copying an empty value
}

// tools lists clipboard programs in order of preference for this system.
func tools() []tool {
	if runtime.GOOS == "darwin" {
		return []tool{{copy: []string{"pbcopy"}, paste: []string{"pbpaste"}}}
	}
	var out []tool
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		out = append(out, tool{copy: []string{"wl-copy"}, paste: []string{"wl-paste", "--no-newline"}, clear: []string{"wl-copy", "--clear"}})
	}
	out = append(out,
		tool{copy: []string{"xclip", "-selection", "clipboard"}, paste: []string{"xclip", "-selection", "clipboard", "-o"}},
		tool{copy: []string{"xsel", "--clipboard", "--input"}, paste: []string{"xsel", "--clipboard", "--output"}, clear: []string{"xsel", "--clipboard", "--clear"}},
		// WSL: the Windows clipboard through interop.
		tool{copy: []string{"clip.exe"}},
	)
	return out
}

func available() (tool, bool) {
	for _, t := range tools() {
		if _, err := exec.LookPath(t.copy[0]); err == nil && (os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" || runtime.GOOS == "darwin" || t.copy[0] == "clip.exe") {
			return t, true
		}
	}
	return tool{}, false
}

func write(value []byte) error {
	t, ok := available()
	if !ok {
		return ErrUnavailable
	}
	cmd := exec.Command(t.copy[0], t.copy[1:]...)
	cmd.Stdin = bytes.NewReader(value)
	return cmd.Run()
}

func read() ([]byte, error) {
	t, ok := available()
	if !ok {
		return nil, ErrUnavailable
	}
	if len(t.paste) == 0 {
		return nil, errNoRead
	}
	return exec.Command(t.paste[0], t.paste[1:]...).Output()
}

func clear() error {
	t, ok := available()
	if !ok {
		return ErrUnavailable
	}
	if len(t.clear) > 0 {
		return exec.Command(t.clear[0], t.clear[1:]...).Run()
	}
	cmd := exec.Command(t.copy[0], t.copy[1:]...)
	cmd.Stdin = bytes.NewReader(nil)
	return cmd.Run()
}
