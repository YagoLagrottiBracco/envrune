// Package agent keeps the vault's data key in a background process for a
// limited time, like ssh-agent, so each new terminal does not ask for the
// master password. It answers on a Unix socket in the user's private data
// directory, or on Windows on a named pipe whose ACL admits only the user,
// and both ends check, where the platform allows, that the other process
// belongs to the same user.
package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"time"
)

var ErrNotRunning = errors.New("agent is not running")

const dialTimeout = time.Second

type request struct {
	Op string `json:"op"`
}

type response struct {
	Key     []byte    `json:"key,omitempty"`
	Expires time.Time `json:"expires"`
	Error   string    `json:"error,omitempty"`
}

// Serve answers key requests on address until ttl passes or a stop request
// arrives. It wipes key before returning.
func Serve(address string, key []byte, ttl time.Duration) error {
	defer wipe(key)
	if _, err := Status(address); err == nil {
		return errors.New("an agent is already running")
	}
	listener, err := listen(address)
	if err != nil {
		return err
	}
	defer listener.Close()
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

func call(address, op string) (response, error) {
	conn, err := dial(address)
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
func Key(address string) ([]byte, error) {
	resp, err := call(address, "key")
	if err != nil {
		return nil, err
	}
	if len(resp.Key) == 0 {
		return nil, ErrNotRunning
	}
	return resp.Key, nil
}

// Status reports when a running agent will forget the key.
func Status(address string) (time.Time, error) {
	resp, err := call(address, "status")
	return resp.Expires, err
}

// Stop asks a running agent to forget the key and exit.
func Stop(address string) error {
	_, err := call(address, "stop")
	return err
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
