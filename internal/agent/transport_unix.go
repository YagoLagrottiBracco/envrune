//go:build !windows

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
)

// maxSocketPath stays under the ~104-byte limit of Unix socket addresses on
// every platform.
const maxSocketPath = 100

// Address returns the agent socket that belongs to the vault at vaultPath:
// next to the vault, or in the user's runtime or temporary directory when
// that path would be too long for a socket.
func Address(vaultPath string) string {
	path := filepath.Join(filepath.Dir(vaultPath), "agent.sock")
	if len(path) <= maxSocketPath {
		return path
	}
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	sum := sha256.Sum256([]byte(vaultPath))
	return filepath.Join(dir, "envrune-"+hex.EncodeToString(sum[:6])+".sock")
}

// listen creates the socket readable and writable only by the user. Closing
// the listener removes the socket file.
func listen(address string) (net.Listener, error) {
	_ = os.Remove(address) // a socket left by an agent that did not exit cleanly
	listener, err := net.Listen("unix", address)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(address, 0600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func dial(address string) (net.Conn, error) {
	return net.DialTimeout("unix", address, dialTimeout)
}
