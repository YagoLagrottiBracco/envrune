package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCLI makes providers run this test binary instead of gh or op; it
// answers as TestHelperProcess describes.
func fakeCLI(t *testing.T, mode string) {
	t.Helper()
	old, oldLook := execCommand, lookPath
	lookPath = func(name string) (string, error) { return name, nil }
	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=TestHelperProcess", "--", name}, args...)...)
		cmd.Env = append(os.Environ(), "ENVRUNE_HELPER="+mode)
		return cmd
	}
	t.Cleanup(func() { execCommand, lookPath = old, oldLook })
}

func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("ENVRUNE_HELPER")
	if mode == "" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	args = args[1:]
	switch mode {
	case "op-item":
		fmt.Print(`{"fields":[
			{"label":"username","value":"svc-user","purpose":"USERNAME"},
			{"label":"Stripe key","value":"sk_live_op_value","type":"CONCEALED"},
			{"label":"notesPlain","value":"some notes","purpose":"NOTES"},
			{"label":"empty","value":""}]}`)
	case "gh-record":
		stdin, _ := io.ReadAll(os.Stdin)
		f, _ := os.OpenFile(os.Getenv("ENVRUNE_HELPER_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		fmt.Fprintf(f, "%s stdin=%s\n", strings.Join(args, " "), stdin)
		f.Close()
	case "fail":
		fmt.Fprint(os.Stderr, "not signed in")
		os.Exit(1)
	}
	os.Exit(0)
}

func TestOnePasswordPullsFieldsAsVariables(t *testing.T) {
	fakeCLI(t, "op-item")
	values, _, err := OnePassword{}.Pull(context.Background(), "development", Options{"item": "Payments"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range values {
		got[v.Name] = string(v.Value)
	}
	if len(got) != 2 || got["USERNAME"] != "svc-user" || got["STRIPE_KEY"] != "sk_live_op_value" {
		t.Fatalf("Pull() = %v", got)
	}
}

func TestVariableNameFromLabels(t *testing.T) {
	for label, want := range map[string]string{"Stripe key": "STRIPE_KEY", "api-token": "API_TOKEN", "2fa code": "_2FA_CODE", "***": ""} {
		if got := variableName(label); got != want {
			t.Fatalf("variableName(%q) = %q, want %q", label, got, want)
		}
	}
}

func TestGitHubPushesValuesThroughStandardInput(t *testing.T) {
	log := filepath.Join(t.TempDir(), "gh.log")
	t.Setenv("ENVRUNE_HELPER_LOG", log)
	fakeCLI(t, "gh-record")
	err := GitHub{}.Push(context.Background(), "production", []Value{{"API_KEY", []byte("sk-gh-value")}}, Options{"repo": "me/app", "github-env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(log)
	if got := string(raw); got != "gh secret set API_KEY --repo me/app --env prod stdin=sk-gh-value\n" {
		t.Fatalf("gh was called as %q", got)
	}
}

// vercelAPI serves the two endpoints the provider uses.
func vercelAPI(t *testing.T, posted *[]map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":{"message":"bad token"}}`)
			return
		}
		if r.URL.Path != "/v10/projects/prj_1/env" || r.URL.Query().Get("teamId") != "team_9" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("decrypt") != "true" {
				t.Error("decrypt=true is missing")
			}
			fmt.Fprint(w, `{"envs":[
				{"key":"DATABASE_URL","value":"postgres://prod","type":"encrypted","decrypted":true,"target":["production","preview"]},
				{"key":"STRIPE_KEY","value":"","type":"sensitive","target":["production"]},
				{"key":"DEV_ONLY","value":"x","type":"plain","target":["development"]},
				{"key":"BRANCH","value":"y","type":"plain","target":["preview"],"gitBranch":"feat"},
				{"key":"PUBLIC_URL","value":"https://example.com","type":"plain","target":"production"}]}`)
		case http.MethodPost:
			if r.URL.Query().Get("upsert") != "true" {
				t.Error("upsert=true is missing")
			}
			_ = json.NewDecoder(r.Body).Decode(posted)
			fmt.Fprint(w, `{}`)
		}
	}))
}

func vercelFor(server *httptest.Server, token string) Vercel {
	return Vercel{BaseURL: server.URL, Client: server.Client(), Getenv: func(k string) string {
		if k == "VERCEL_TOKEN" {
			return token
		}
		return ""
	}}
}

func linkedVercelDir(t *testing.T) string {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".vercel"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".vercel", "project.json"), []byte(`{"projectId":"prj_1","orgId":"team_9"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestVercelPullsOneTargetAndNamesWhatItCannotRead(t *testing.T) {
	server := vercelAPI(t, nil)
	defer server.Close()
	values, notes, err := vercelFor(server, "test-token").Pull(context.Background(), "production", Options{"dir": linkedVercelDir(t)})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, v := range values {
		got[v.Name] = string(v.Value)
	}
	if len(got) != 2 || got["DATABASE_URL"] != "postgres://prod" || got["PUBLIC_URL"] != "https://example.com" {
		t.Fatalf("Pull() = %v", got)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "STRIPE_KEY is a sensitive Vercel variable") {
		t.Fatalf("notes = %v", notes)
	}
}

func TestVercelPushUpsertsEncryptedVariables(t *testing.T) {
	var posted []map[string]any
	server := vercelAPI(t, &posted)
	defer server.Close()
	err := vercelFor(server, "test-token").Push(context.Background(), "staging", []Value{{"API_KEY", []byte("sk-vercel-value")}}, Options{"dir": linkedVercelDir(t), "target": "preview"})
	if err != nil {
		t.Fatal(err)
	}
	if len(posted) != 1 || posted[0]["key"] != "API_KEY" || posted[0]["value"] != "sk-vercel-value" || posted[0]["type"] != "encrypted" || fmt.Sprint(posted[0]["target"]) != "[preview]" {
		t.Fatalf("posted %v", posted)
	}
}

func TestVercelExplainsMissingTokenTargetAndLink(t *testing.T) {
	server := vercelAPI(t, nil)
	defer server.Close()
	ctx := context.Background()
	if _, _, err := vercelFor(server, "").Pull(ctx, "production", Options{"dir": linkedVercelDir(t)}); err == nil || !strings.Contains(err.Error(), "VERCEL_TOKEN") {
		t.Fatalf("missing token: %v", err)
	}
	if _, _, err := vercelFor(server, "test-token").Pull(ctx, "staging", Options{"dir": linkedVercelDir(t)}); err == nil || !strings.Contains(err.Error(), "--target") {
		t.Fatalf("unknown target: %v", err)
	}
	if _, _, err := vercelFor(server, "test-token").Pull(ctx, "production", Options{"dir": t.TempDir()}); err == nil || !strings.Contains(err.Error(), "vercel link") {
		t.Fatalf("no link: %v", err)
	}
	if _, _, err := vercelFor(server, "wrong").Pull(ctx, "production", Options{"dir": linkedVercelDir(t)}); err == nil || !strings.Contains(err.Error(), "401: bad token") {
		t.Fatalf("bad token: %v", err)
	}
}
