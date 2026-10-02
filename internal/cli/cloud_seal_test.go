package cli

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// sensitiveServer plays the routes a command with a sensitive secret needs,
// with real keys: alice founds acme and seals payments-key for
// api.example.com. Forwarded requests are answered as a service would,
// after the placeholder is replaced by the value; what the "service"
// received is recorded.
type sensitiveServer struct {
	srv      *httptest.Server
	state    string // the cloud state of alice's device
	mu       sync.Mutex
	received []string
}

func newSensitiveServer(t *testing.T, hosts []string) *sensitiveServer {
	t.Helper()
	const user, org, project, env = "alice", "org-1", "p1", "e1"
	account, err := cloudcrypto.NewAccount(user)
	if err != nil {
		t.Fatal(err)
	}
	device, err := cloudcrypto.NewDevice(user, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	cert := account.CertifyDevice(device.DeviceID, device.Identity.Recipient().String(), device.SigningPublic())
	proxy, _ := age.GenerateX25519Identity()
	record, err := device.SealSensitive(org, project, env, "payments-key", 1, []byte("the-real-value"), hosts, proxy.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	s := &sensitiveServer{}
	snapshot := map[string]any{
		"id": org, "slug": "acme", "name": "Acme",
		"roots": []map[string]any{{"user_id": user, "account_key": []byte(account.Public)}},
		"devices": []map[string]any{{"user_id": user, "id": device.DeviceID, "kind": "device", "age_recipient": cert.AgeRecipient,
			"signing_key": []byte(cert.SigningKey), "created_at_us": cert.CreatedAt.UnixMicro(), "signature": cert.Signature}},
		"projects": []map[string]any{{"id": project, "slug": "shop", "environments": []map[string]any{{"id": env, "slug": "production", "epoch": 1}}}},
		"sensitive": []map[string]any{{"environment_id": env, "name": record.Name, "version": 1, "hosts": record.Hosts,
			"proxy_recipient": record.ProxyRecipient, "sealed_hash": record.SealedHash, "writer_user_id": user,
			"writer_device_id": device.DeviceID, "signature": record.Signature}},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/orgs/acme", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(snapshot) })
	mux.HandleFunc("GET /api/v1/versions", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{env: map[string]any{"epoch": 1, "secrets": map[string]int{}, "sensitive": map[string]int{"payments-key": 1}}})
	})
	mux.HandleFunc("/api/v1/forward", func(w http.ResponseWriter, r *http.Request) {
		var named []struct{ Name, Placeholder string }
		var headers [][2]string
		raw, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-EnvRune-Secrets"))
		_ = json.Unmarshal(raw, &named)
		raw, _ = base64.StdEncoding.DecodeString(r.Header.Get("X-EnvRune-Headers"))
		_ = json.Unmarshal(raw, &headers)
		body, _ := io.ReadAll(r.Body)
		line := r.Method + " " + r.Header.Get("X-EnvRune-Target")
		for _, h := range headers {
			if strings.EqualFold(h[0], "Authorization") {
				line += " " + h[1]
			}
		}
		line += " " + string(body)
		for _, n := range named {
			line = strings.ReplaceAll(line, n.Placeholder, "the-real-value")
		}
		s.mu.Lock()
		s.received = append(s.received, line)
		s.mu.Unlock()
		w.Header().Set("X-EnvRune-Forward", "upstream")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"charged":true}`)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	state, _ := json.Marshal(map[string]any{
		"server": s.srv.URL, "user_id": user, "tokens": map[string]string{"access_token": "a.b.c"},
		"account_seed": account.Seed(), "device_id": device.DeviceID, "device_identity": device.Identity.String(),
		"device_signing_seed": device.SigningSeed(), "device_approved": true,
		"orgs": map[string]any{"acme": map[string]any{"id": org, "roots": map[string][]byte{user: account.Public},
			"cache": map[string]any{"shop/production": map[string]any{"project_id": project, "environment_id": env,
				"payload": map[string]any{"epoch": 1}, "fetched_at": "2026-10-01T00:00:00Z"}}}},
	})
	s.state = string(state)
	return s
}

const sensitiveConfig = "version: 1\nproject: shop\ncloud: acme/shop\ndefault_env: production\nenvironments:\n  production:\n    PAYMENTS_KEY: cloud.payments-key\n"

func TestAProgramUsesASensitiveSecretThroughRun(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil || runtime.GOOS == "windows" {
		t.Skip("needs curl and a POSIX shell, as a program that honours the proxy variables")
	}
	server := newSensitiveServer(t, []string{"api.example.com"})
	f := newFixture(t, sensitiveConfig)
	if err := f.session.UpdateCloudState(func([]byte) ([]byte, error) { return []byte(server.state), nil }); err != nil {
		t.Fatal(err)
	}

	// The program is given a placeholder, which it prints and sends; the
	// service receives the value, and the program never does.
	script := `echo "key=$PAYMENTS_KEY"; curl -sS --max-time 20 -X POST https://api.example.com/v1/charges -H "Authorization: Bearer $PAYMENTS_KEY" -d "token=$PAYMENTS_KEY"`
	code := f.run("run", "--no-redact", "--", "sh", "-c", script)
	out := f.output()
	if code != 0 {
		t.Fatalf("run = %d:\n%s", code, out)
	}
	if !strings.Contains(out, "key=envrune_sealed_") || !strings.Contains(out, `{"charged":true}`) {
		t.Fatalf("the program did not get a placeholder and an answer:\n%s", out)
	}
	if strings.Contains(out, "the-real-value") {
		t.Fatalf("the value reached this computer:\n%s", out)
	}
	if !strings.Contains(out, "payments-key never reaches this computer") || !strings.Contains(out, "api.example.com") {
		t.Fatalf("the user was not told what happens:\n%s", out)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	want := "POST https://api.example.com/v1/charges Bearer the-real-value token=the-real-value"
	if len(server.received) != 1 || server.received[0] != want {
		t.Fatalf("the service received %q", server.received)
	}
}

func TestSensitiveSecretsAreNotShownOrExported(t *testing.T) {
	server := newSensitiveServer(t, []string{"api.example.com"})
	f := newFixture(t, sensitiveConfig)
	if err := f.session.UpdateCloudState(func([]byte) ([]byte, error) { return []byte(server.state), nil }); err != nil {
		t.Fatal(err)
	}
	// Learn which names are sensitive, as any command online does.
	f.workspace().freshen(f.projectPath, "")
	for _, args := range [][]string{{"env", "--format", "json"}, {"export", "--output", t.TempDir() + "/.env"}, {"copy", "cloud.payments-key"}} {
		code := f.run(args...)
		if code == 0 || strings.Contains(f.output(), "envrune_sealed_") {
			t.Errorf("%s = %d: %s", args[0], code, f.output())
		}
	}
}

func TestUpGivesEachServiceItsSensitiveSecrets(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil || runtime.GOOS == "windows" {
		t.Skip("needs curl and a POSIX shell")
	}
	server := newSensitiveServer(t, []string{"api.example.com"})
	config := sensitiveConfig + "commands:\n  pay:\n    run: " +
		`"sh -c 'curl -sS --max-time 20 https://api.example.com/v1/me -H \"Authorization: Bearer $PAYMENTS_KEY\"'"` + "\n"
	f := newFixture(t, config)
	if err := f.session.UpdateCloudState(func([]byte) ([]byte, error) { return []byte(server.state), nil }); err != nil {
		t.Fatal(err)
	}
	if code := f.run("up", "--no-redact"); code != 0 {
		t.Fatalf("up = %d:\n%s", code, f.output())
	}
	if out := f.output(); !strings.Contains(out, `{"charged":true}`) || strings.Contains(out, "the-real-value") {
		t.Fatalf("up output:\n%s", out)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.received) != 1 || !strings.Contains(server.received[0], "Bearer the-real-value") {
		t.Fatalf("the service received %q", server.received)
	}
}
