package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func shortTempDir(t *testing.T) string {
	t.Helper()
	// Unix socket paths are limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "ea")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestAgentServesKeyUntilStopped(t *testing.T) {
	socket := filepath.Join(shortTempDir(t), "a.sock")
	key := bytes.Repeat([]byte{7}, 32)
	done := make(chan error, 1)
	go func() { done <- Serve(socket, append([]byte(nil), key...), time.Minute) }()
	var got []byte
	var err error
	for i := 0; i < 100; i++ {
		if got, err = Key(socket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("Key() = %x, %v", got, err)
	}
	if err := Stop(socket); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := Key(socket); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Key() after stop = %v", err)
	}
}

func TestAgentForgetsKeyAfterTTL(t *testing.T) {
	socket := filepath.Join(shortTempDir(t), "a.sock")
	if err := Serve(socket, bytes.Repeat([]byte{1}, 32), 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := Key(socket); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("Key() after TTL = %v", err)
	}
}
