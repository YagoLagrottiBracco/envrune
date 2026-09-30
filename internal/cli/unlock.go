package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/agent"
	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/keychain"
	"github.com/YagoLagrottiBracco/envrune/internal/paths"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

// ErrLocked means no unlock method works without a prompt, such as in a
// terminal hook.
var ErrLocked = errors.New("the vault is locked")

// vaultPath honors ENVRUNE_VAULT, which points at one vault file, such as a
// vault shared between Windows and WSL or restored in CI.
func vaultPath(getenv func(string) string) (string, error) {
	if path := getenv("ENVRUNE_VAULT"); path != "" {
		return filepath.Abs(path)
	}
	return paths.VaultPath(getenv, os.UserHomeDir)
}

func keychainMarker(vaultPath string) string {
	return filepath.Join(filepath.Dir(vaultPath), "keychain.enabled")
}

func keychainEnabled(vaultPath string) bool {
	_, err := os.Stat(keychainMarker(vaultPath))
	return err == nil
}

// unlocker opens the vault with the first method that works, in order:
//
//  1. ENVRUNE_PASSWORD_FILE or ENVRUNE_PASSWORD, for CI;
//  2. ENVRUNE_IDENTITY or ENVRUNE_TOKEN when there is no vault, for team
//     and EnvRune Cloud secrets in CI;
//  3. a running agent started by `envrune unlock`;
//  4. the system keychain, after `envrune keychain enable`;
//  5. the master password prompt.
//
// With ENVRUNE_TOKEN, a machine token, cloud references resolve from the
// server whatever opened the session, verified against the roots the token
// pins (see cloudSource).
type unlocker struct {
	getenv   func(string) string
	prompt   func(string) ([]byte, error)
	noPrompt bool
	status   Presenter
}

func (u unlocker) session() (*app.Session, error) {
	session, err := u.open()
	if err != nil {
		return nil, err
	}
	if token := strings.TrimSpace(u.getenv("ENVRUNE_TOKEN")); token != "" {
		session.UseCloudSource(machineSource(token, u.getenv))
	}
	return session, nil
}

// machineSource fetches cloud environments with a machine token, from
// ENVRUNE_CLOUD_SERVER or the default server.
func machineSource(token string, getenv func(string) string) app.CloudSource {
	return func(path cloud.Path) (map[string][]byte, string, error) {
		server := getenv("ENVRUNE_CLOUD_SERVER")
		if server == "" {
			server = cloud.DefaultServer
		}
		if server == "" {
			return nil, "", errors.New("set ENVRUNE_CLOUD_SERVER to the EnvRune Cloud address for ENVRUNE_TOKEN")
		}
		ctx, cancel := context.WithTimeout(context.Background(), cloudTimeout)
		defer cancel()
		values, err := cloud.MachineValues(ctx, nil, server, token, path)
		return values, "", err
	}
}

func (u unlocker) open() (*app.Session, error) {
	path, err := vaultPath(u.getenv)
	if err != nil {
		return nil, err
	}
	if password, ok, err := passwordFromEnvironment(u.getenv); ok {
		if err != nil {
			return nil, err
		}
		defer wipe(password)
		return app.OpenSession(path, password)
	}
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		identity, token := u.getenv("ENVRUNE_IDENTITY"), u.getenv("ENVRUNE_TOKEN")
		if identity != "" || token != "" {
			return app.NewIdentitySession(strings.TrimSpace(identity)), nil
		}
		return nil, vault.ErrNotFound
	}
	if key, err := agent.Key(agent.Address(path)); err == nil {
		defer wipe(key)
		if v, err := vault.OpenWithKey(path, key); err == nil {
			return app.NewSession(v), nil
		}
	}
	if keychainEnabled(path) {
		if key, err := keychain.Get(keychain.Account(path)); err == nil {
			defer wipe(key)
			if v, err := vault.OpenWithKey(path, key); err == nil {
				return app.NewSession(v), nil
			}
		}
		u.status.Warn("The system keychain did not unlock the vault; falling back to the master password.")
	}
	if u.noPrompt {
		return nil, ErrLocked
	}
	password, err := u.prompt("Master password")
	if err != nil {
		return nil, err
	}
	defer wipe(password)
	return app.OpenSession(path, password)
}

func passwordFromEnvironment(getenv func(string) string) ([]byte, bool, error) {
	if file := getenv("ENVRUNE_PASSWORD_FILE"); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, true, err
		}
		return []byte(strings.TrimRight(string(raw), "\r\n")), true, nil
	}
	if password := getenv("ENVRUNE_PASSWORD"); password != "" {
		return []byte(password), true, nil
	}
	return nil, false, nil
}
