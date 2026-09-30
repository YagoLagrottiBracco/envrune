package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

var errOtherUser = errors.New("the agent pipe belongs to another user")

// Address returns the named pipe of the agent for the vault at vaultPath.
// Pipe names are global to the machine, so the name also depends on the
// user's SID; the pipe ACL, not the name, is what keeps other users out.
func Address(vaultPath string) string {
	owner := "unknown"
	if sid, err := currentSID(); err == nil {
		owner = sid.String()
	}
	sum := sha256.Sum256([]byte(owner + "\x00" + strings.ToLower(filepath.Clean(vaultPath))))
	return `\\.\pipe\envrune-agent-` + hex.EncodeToString(sum[:12])
}

// listen creates the pipe with a protected DACL that grants access to the
// current user only, so administrators, other users, and processes of lower
// integrity cannot open it. go-winio also rejects remote clients and fails
// if another process created the pipe first.
func listen(address string) (net.Listener, error) {
	sid, err := currentSID()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(address, &winio.PipeConfig{SecurityDescriptor: "D:P(A;;GA;;;" + sid.String() + ")"})
}

// dial connects only to a pipe served by a process of the same user, so a
// pipe created first by someone else cannot pose as the agent.
func dial(address string) (net.Conn, error) {
	timeout := dialTimeout
	conn, err := winio.DialPipe(address, &timeout)
	if err != nil {
		return nil, err
	}
	if !sameUser(conn, windows.GetNamedPipeServerProcessId) {
		_ = conn.Close()
		return nil, errOtherUser
	}
	return conn, nil
}

// peerAllowed accepts only clients of the same user. The pipe ACL already
// enforces it; this is a second check.
func peerAllowed(conn net.Conn) bool {
	return sameUser(conn, windows.GetNamedPipeClientProcessId)
}

func hardenProcess() {}

// sameUser reports whether the process at the other end of the pipe, found
// with processID, runs as the current user.
func sameUser(conn net.Conn, processID func(windows.Handle, *uint32) error) bool {
	file, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return false
	}
	var pid uint32
	if processID(windows.Handle(file.Fd()), &pid) != nil {
		return false
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token) != nil {
		return false
	}
	defer token.Close()
	peer, err := token.GetTokenUser()
	if err != nil {
		return false
	}
	me, err := currentSID()
	return err == nil && windows.EqualSid(peer.User.Sid, me)
}

func currentSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	return user.User.Sid, nil
}
