package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// sleepCommand returns a commands: entry that runs for a long time.
func sleepCommand() string {
	if runtime.GOOS == "windows" {
		return "ping -n 60 127.0.0.1"
	}
	return "sleep 60"
}

type mcpFixture struct {
	*fixture
	server mcpServer
	locked bool
}

func newMCPFixture(t *testing.T) *mcpFixture {
	t.Helper()
	config := baseConfig + "commands:\n  hello: " + echoCommand("hello") + "\n  slow: " + sleepCommand() + "\n"
	f := &mcpFixture{fixture: newFixture(t, config)}
	if err := f.session.Set("demo.api-key", []byte("sk-mcp-secret-value")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Set("demo.unused", []byte("unused-secret-value")); err != nil {
		t.Fatal(err)
	}
	if err := f.session.Link(f.projectPath, "development", "API_KEY", "demo.api-key"); err != nil {
		t.Fatal(err)
	}
	f.server = mcpServer{
		dir: filepath.Dir(f.projectPath),
		open: func() (*app.Session, error) {
			if f.locked {
				return nil, ErrLocked
			}
			return app.OpenSession(f.vaultPath, []byte("fixture-password"))
		},
	}
	return f
}

func (f *mcpFixture) call(t *testing.T, server mcpServer, name string, args map[string]any) (*mcp.CallToolResult, string) {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.server().Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	client, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	raw, _ := json.Marshal(result)
	for _, value := range []string{"sk-mcp-secret-value", "unused-secret-value"} {
		if strings.Contains(string(raw), value) {
			t.Fatalf("%s returned a secret value: %s", name, raw)
		}
	}
	return result, string(raw)
}

func toolNames(t *testing.T, server mcpServer) map[string]bool {
	t.Helper()
	ctx := context.Background()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	if _, err := server.server().Connect(ctx, serverTransport, nil); err != nil {
		t.Fatal(err)
	}
	client, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	names := map[string]bool{}
	for tool, err := range client.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		names[tool.Name] = true
	}
	return names
}

func TestMCPRunsNamedCommandsWithMaskedOutput(t *testing.T) {
	f := newMCPFixture(t)
	result, raw := f.call(t, f.server, "run_command", map[string]any{"name": "hello"})
	if result.IsError || !strings.Contains(raw, "hello ****") || !strings.Contains(raw, `"exit_code":0`) {
		t.Fatalf("run_command = %s", raw)
	}
	if result, raw := f.call(t, f.server, "run_command", map[string]any{"name": "hello", "args": []string{"x"}}); !result.IsError || !strings.Contains(raw, "--allow-args") {
		t.Fatalf("run_command with args = %s", raw)
	}
	if result, raw := f.call(t, f.server, "run_command", map[string]any{"name": "printenv"}); !result.IsError || !strings.Contains(raw, "list_commands") {
		t.Fatalf("run_command with an unknown name = %s", raw)
	}
	if _, raw := f.call(t, f.server, "list_commands", nil); !strings.Contains(raw, `"name":"hello"`) || !strings.Contains(raw, `"name":"slow"`) {
		t.Fatalf("list_commands = %s", raw)
	}
	if _, raw := f.call(t, f.server, "list_variables", nil); !strings.Contains(raw, `"reference":"demo.api-key"`) || !strings.Contains(raw, `"stored":true`) {
		t.Fatalf("list_variables = %s", raw)
	}
	if _, raw := f.call(t, f.server, "list_environments", nil); !strings.Contains(raw, `"default":"development"`) {
		t.Fatalf("list_environments = %s", raw)
	}
	if _, raw := f.call(t, f.server, "doctor", nil); !strings.Contains(raw, "findings") {
		t.Fatalf("doctor = %s", raw)
	}
}

func TestMCPStopsCommandsAtTheTimeout(t *testing.T) {
	f := newMCPFixture(t)
	started := time.Now()
	result, raw := f.call(t, f.server, "run_command", map[string]any{"name": "slow", "timeout_seconds": 1})
	if result.IsError || !strings.Contains(raw, `"timed_out":true`) {
		t.Fatalf("run_command = %s", raw)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("the timeout took %s", elapsed)
	}
}

func TestMCPAsksForUnlockInsteadOfPrompting(t *testing.T) {
	f := newMCPFixture(t)
	f.locked = true
	result, raw := f.call(t, f.server, "run_command", map[string]any{"name": "hello"})
	if !result.IsError || !strings.Contains(raw, "envrune unlock") {
		t.Fatalf("run_command while locked = %s", raw)
	}
	if result, raw := f.call(t, f.server, "list_variables", nil); result.IsError || !strings.Contains(raw, "locked") {
		t.Fatalf("list_variables while locked = %s", raw)
	}
}

func TestMCPOffersAnyCommandOnlyWhenAllowed(t *testing.T) {
	f := newMCPFixture(t)
	allowed := f.server
	allowed.allowAny = true
	if has := toolNames(t, f.server)["run_any_command"]; has {
		t.Fatal("run_any_command exists without --allow-any-command")
	}
	if has := toolNames(t, allowed)["run_any_command"]; !has {
		t.Fatal("run_any_command is missing with --allow-any-command")
	}
	command := []string{"sh", "-c", "echo any $API_KEY"}
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "echo any %API_KEY%"}
	}
	result, raw := f.call(t, allowed, "run_any_command", map[string]any{"command": command})
	if result.IsError || !strings.Contains(raw, "any ****") {
		t.Fatalf("run_any_command = %s", raw)
	}
}

func TestMCPRefusesAnyCommandWithAConsumersValues(t *testing.T) {
	f := newMCPFixture(t)
	config := "version: 1\nproject: shop\ncloud: acme/shop\ndefault_env: production\nenvironments:\n  production:\n    STRIPE_KEY: cloud.stripe-key\n" +
		"commands:\n  hello: " + echoCommand("hello") + "\n"
	if err := os.WriteFile(f.projectPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	role := cloudcrypto.RoleConsumer
	server := f.server
	server.allowAny = true
	server.open = func() (*app.Session, error) {
		session, err := app.OpenSession(f.vaultPath, []byte("fixture-password"))
		if err != nil {
			return nil, err
		}
		session.UseCloudSource(func(cloud.Path) (map[string][]byte, string, error) {
			return map[string][]byte{"stripe-key": []byte("sk_live_consumer_value")}, role, nil
		})
		return session, nil
	}
	command := []string{"sh", "-c", "echo any"}
	if runtime.GOOS == "windows" {
		command = []string{"cmd", "/c", "echo any"}
	}
	result, raw := f.call(t, server, "run_any_command", map[string]any{"command": command})
	if !result.IsError || !strings.Contains(raw, "consumer") || strings.Contains(raw, "sk_live_consumer_value") {
		t.Fatalf("run_any_command for a consumer = %s", raw)
	}
	// The project's own commands still run, and a maintainer keeps the tool.
	if result, raw := f.call(t, server, "run_command", map[string]any{"name": "hello"}); result.IsError {
		t.Fatalf("run_command for a consumer = %s", raw)
	}
	role = cloudcrypto.RoleMaintainer
	if result, raw := f.call(t, server, "run_any_command", map[string]any{"command": command}); result.IsError {
		t.Fatalf("run_any_command for a maintainer = %s", raw)
	}
}
