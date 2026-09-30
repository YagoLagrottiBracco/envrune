//go:build windows

package clipboard

import "testing"

func TestWindowsClipboardRoundTripAndClear(t *testing.T) {
	previous, _ := read()
	defer func() {
		if previous != nil {
			_ = write(previous)
		}
	}()
	if err := write([]byte("envrune-clipboard-test")); err != nil {
		t.Skipf("clipboard unavailable: %v", err)
	}
	got, err := read()
	if err != nil || string(got) != "envrune-clipboard-test" {
		t.Fatalf("read() = %q, %v", got, err)
	}
	if err := clear(); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(); len(got) != 0 {
		t.Fatalf("clipboard not cleared: %q", got)
	}
}
