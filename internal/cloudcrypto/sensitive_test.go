package cloudcrypto

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"filippo.io/age"
)

func TestSensitiveValuesOpenOnlyForTheProxyAndTheirPlace(t *testing.T) {
	device, err := NewDevice("alice", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	proxy, _ := age.GenerateX25519Identity()
	other, _ := age.GenerateX25519Identity()
	r, err := device.SealSensitive("org", "project", "env", "payments-key", 3, []byte("the-real-value"), []string{"API.example.com ", "b.example.org", "api.example.com"}, proxy.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.Hosts, []string{"api.example.com", "b.example.org"}) {
		t.Fatalf("hosts = %v", r.Hosts)
	}
	if err := r.Verify(device.SigningPublic()); err != nil {
		t.Fatal(err)
	}
	content, err := OpenSensitive(r, proxy)
	if err != nil || string(content.Value) != "the-real-value" || !slices.Equal(content.Hosts, r.Hosts) {
		t.Fatalf("the proxy opened %+v: %v", content, err)
	}
	if _, err := OpenSensitive(r, other); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("another identity opened it: %v", err)
	}

	// The readable copy of the hosts is signed; the ones acted on are sealed.
	forged := *r
	forged.Hosts = []string{"evil.example.net"}
	if err := forged.Verify(device.SigningPublic()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("changed hosts verified: %v", err)
	}
	if content, _ := OpenSensitive(&forged, proxy); content == nil || slices.Contains(content.Hosts, "evil.example.net") {
		t.Fatalf("the sealed hosts changed with the copy: %+v", content)
	}
	// A device verifies who marked it from the hash alone, without the
	// ciphertext.
	listed := *r
	listed.Sealed = nil
	if err := listed.Verify(device.SigningPublic()); err != nil {
		t.Fatalf("the record did not verify from its hash: %v", err)
	}
	listed.SealedHash = make([]byte, 32)
	if err := listed.Verify(device.SigningPublic()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("another ciphertext verified: %v", err)
	}
	// A record moved to another secret, version, or environment does not open.
	for name, move := range map[string]func(*SensitiveRecord){
		"name":        func(m *SensitiveRecord) { m.Name = "other" },
		"version":     func(m *SensitiveRecord) { m.Version = 4 },
		"environment": func(m *SensitiveRecord) { m.EnvironmentID = "staging" },
	} {
		moved := *r
		move(&moved)
		if _, err := OpenSensitive(&moved, proxy); !errors.Is(err, ErrDecrypt) {
			t.Errorf("a record with another %s opened: %v", name, err)
		}
	}
}

func TestSensitiveHostsAreFullNames(t *testing.T) {
	for _, bad := range [][]string{nil, {"*.example.com"}, {"example"}, {"10.0.0.1"}, {"https://api.example.com"}, {"api.example.com/v1"}, {"api.example.com:8443"}, {"localhost"}} {
		if _, err := NormalizeHosts(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%v was accepted: %v", bad, err)
		}
	}
	if hosts, err := NormalizeHosts([]string{"api.pagamentos.example.com.br"}); err != nil || len(hosts) != 1 {
		t.Fatalf("a full name was refused: %v", err)
	}
}

// sensitiveVectorPath holds a sensitive record sealed by this package, which
// the server (cloud/web) opens with its own age implementation. Sealing is
// randomized, so the file is written once (ENVRUNE_WRITE_VECTORS=1) and both
// sides check that it still opens.
var sensitiveVectorPath = filepath.Join("..", "..", "cloud", "web", "src", "lib", "sensitive-vector.json")

type sensitiveVector struct {
	Identity  string `json:"identity"` // a test key, used nowhere else
	Recipient string `json:"recipient"`
	Row       struct {
		OrgID         string `json:"org_id"`
		ProjectID     string `json:"project_id"`
		EnvironmentID string `json:"environment_id"`
		Name          string `json:"name"`
		Version       uint64 `json:"version"`
		Sealed        []byte `json:"sealed"`
	} `json:"row"`
	Hosts []string `json:"hosts"`
	Value string   `json:"value"`
}

func TestSensitiveCrossLanguageVector(t *testing.T) {
	if os.Getenv("ENVRUNE_WRITE_VECTORS") != "" {
		identity, _ := age.GenerateX25519Identity()
		device, _ := NewDevice("alice", "laptop")
		r, err := device.SealSensitive("org-1", "project-1", "env-1", "payments-key", 2, []byte("the-real-value é ✓"), []string{"api.example.com", "b.example.org"}, identity.Recipient().String())
		if err != nil {
			t.Fatal(err)
		}
		v := sensitiveVector{Identity: identity.String(), Recipient: r.ProxyRecipient, Hosts: r.Hosts, Value: "the-real-value é ✓"}
		v.Row.OrgID, v.Row.ProjectID, v.Row.EnvironmentID, v.Row.Name, v.Row.Version, v.Row.Sealed = r.OrgID, r.ProjectID, r.EnvironmentID, r.Name, r.Version, r.Sealed
		raw, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(sensitiveVectorPath, append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(sensitiveVectorPath)
	if err != nil {
		t.Skipf("no vector file (%v); write it with ENVRUNE_WRITE_VECTORS=1", err)
	}
	var v sensitiveVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	identity, err := age.ParseX25519Identity(v.Identity)
	if err != nil {
		t.Fatal(err)
	}
	record := &SensitiveRecord{OrgID: v.Row.OrgID, ProjectID: v.Row.ProjectID, EnvironmentID: v.Row.EnvironmentID, Name: v.Row.Name, Version: v.Row.Version, Sealed: v.Row.Sealed}
	content, err := OpenSensitive(record, identity)
	if err != nil || string(content.Value) != v.Value || !slices.Equal(content.Hosts, v.Hosts) {
		t.Fatalf("the vector opened as %+v: %v", content, err)
	}
}
