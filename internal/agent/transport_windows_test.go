package agent

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func TestAgentPipeAdmitsOnlyTheCurrentUser(t *testing.T) {
	address := Address(filepath.Join(shortTempDir(t), "vault.envrune"))
	if !strings.HasPrefix(address, `\\.\pipe\envrune-agent-`) {
		t.Fatalf("Address() = %q", address)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(address, bytes.Repeat([]byte{3}, 32), time.Minute) }()
	defer func() { _ = Stop(address); <-done }()
	var conn interface {
		Fd() uintptr
		Close() error
	}
	for i := 0; i < 100 && conn == nil; i++ {
		timeout := time.Second
		if c, err := winio.DialPipe(address, &timeout); err == nil {
			conn = c.(interface {
				Fd() uintptr
				Close() error
			})
		} else {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if conn == nil {
		t.Fatal("agent pipe did not open")
	}
	defer conn.Close()
	sd, err := windows.GetSecurityInfo(windows.Handle(conn.Fd()), windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	me, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	// Windows prints well-known accounts by alias (LA for the built-in
	// administrator, which CI runs as), so compare with the descriptor it
	// builds for this user rather than with the SID's text.
	want, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + me.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	if sddl := sd.String(); sddl != want.String() || strings.Count(sddl, "(A;") != 1 {
		t.Fatalf("pipe DACL = %s, want %s: a protected DACL for %s only", sddl, want, me)
	}
}

func TestAddressDependsOnVaultPath(t *testing.T) {
	if Address(`C:\a\vault.envrune`) == Address(`C:\b\vault.envrune`) {
		t.Fatal("two vaults share an agent pipe")
	}
	if Address(`C:\A\Vault.envrune`) != Address(`c:\a\vault.envrune`) {
		t.Fatal("pipe name depends on path case")
	}
}
