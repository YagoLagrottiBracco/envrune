// Package agent keeps the vault's data key in a background process for a
// limited time, like ssh-agent, so each new terminal does not ask for the
// master password. It answers only on a Unix socket in the user's private
// data directory and, where the platform allows, only to the same user.
package agent

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"
)

var ErrNotRunning = errors.New("agent is not running")

const dialTimeout = time.Second

// maxSocketPath stays under the ~104-byte limit of Unix socket addresses on
// every platform.
const maxSocketPath = 100

// SocketPath returns the agent socket that belongs to the vault at vaultPath:
// next to the vault, or in the user's runtime or temporary directory when
// that path would be too long for a socket.
func SocketPath(vaultPath string) string {
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

type request struct {
	Op string `json:"op"`
}

type response struct {
	Key     []byte    `json:"key,omitempty"`
	Expires time.Time `json:"expires"`
	Error   string    `json:"error,omitempty"`
}

// Serve answers key requests until ttl passes or a stop request arrives. It
// wipes key before returning.
func Serve(socketPath string, key []byte, ttl time.Duration) error {
	defer wipe(key)
	if _, err := Status(socketPath); err == nil {
		return errors.New("an agent is already running")
	}
	_ = os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(socketPath, 0600)
	defer os.Remove(socketPath)
	expires := time.Now().Add(ttl)
	timer := time.AfterFunc(ttl, func() { _ = listener.Close() })
	defer timer.Stop()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return nil // closed by the timer or a stop request
		}
		if handle(conn, key, expires) {
			_ = listener.Close()
		}
	}
}

func handle(conn net.Conn, key []byte, expires time.Time) (stop bool) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if !peerAllowed(conn) {
		return false
	}
	var req request
	if json.NewDecoder(bufio.NewReader(conn)).Decode(&req) != nil {
		return false
	}
	encoder := json.NewEncoder(conn)
	switch req.Op {
	case "key":
		_ = encoder.Encode(response{Key: key, Expires: expires})
	case "status":
		_ = encoder.Encode(response{Expires: expires})
	case "stop":
		_ = encoder.Encode(response{Expires: time.Now()})
		return true
	default:
		_ = encoder.Encode(response{Error: "unknown request"})
	}
	return false
}

func call(socketPath, op string) (response, error) {
	conn, err := net.DialTimeout("unix", socketPath, dialTimeout)
	if err != nil {
		return response{}, ErrNotRunning
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if err := json.NewEncoder(conn).Encode(request{Op: op}); err != nil {
		return response{}, ErrNotRunning
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return response{}, ErrNotRunning
	}
	if resp.Error != "" {
		return response{}, errors.New(resp.Error)
	}
	return resp, nil
}

// Key asks a running agent for the data key.
func Key(socketPath string) ([]byte, error) {
	resp, err := call(socketPath, "key")
	if err != nil {
		return nil, err
	}
	if len(resp.Key) == 0 {
		return nil, ErrNotRunning
	}
	return resp.Key, nil
}

// Status reports when a running agent will forget the key.
func Status(socketPath string) (time.Time, error) {
	resp, err := call(socketPath, "status")
	return resp.Expires, err
}

// Stop asks a running agent to forget the key and exit.
func Stop(socketPath string) error {
	_, err := call(socketPath, "stop")
	return err
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
