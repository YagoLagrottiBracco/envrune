package cli

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/agent"
)

func TestStatusReportsStateWithoutUnlocking(t *testing.T) {
	f := newFixture(t, baseConfig)
	getenv := func(k string) string {
		if k == "ENVRUNE_VAULT" {
			return f.vaultPath
		}
		return ""
	}
	s, err := readStatus(getenv, filepath.Dir(f.projectPath))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Exists || s.Unlocked || s.Project != f.projectPath || s.DefaultEnv != "development" || s.promptWord() != "locked" {
		t.Fatalf("status = %+v, prompt %q", s, s.promptWord())
	}

	key, err := f.session.Key()
	if err != nil {
		t.Fatal(err)
	}
	address := agent.Address(f.vaultPath)
	done := make(chan error, 1)
	go func() { done <- agent.Serve(address, key, 3*time.Hour) }()
	defer func() { _ = agent.Stop(address); <-done }()
	for i := 0; i < 100; i++ {
		if _, err := agent.Status(address); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	s, _ = readStatus(getenv, filepath.Dir(f.projectPath))
	if !s.Unlocked || s.promptWord() != "unlocked 2h" {
		t.Fatalf("unlocked status = %+v, prompt %q", s, s.promptWord())
	}

	missing := vaultStatus{}
	if missing.promptWord() != "no vault" {
		t.Fatalf("prompt without a vault = %q", missing.promptWord())
	}
	keychain := vaultStatus{Exists: true, Keychain: true}
	if keychain.promptWord() != "keychain" {
		t.Fatalf("prompt with the keychain = %q", keychain.promptWord())
	}
}
