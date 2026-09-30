//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPServerOverStdio starts `envrune mcp` the way an editor does and
// runs a named command through it.
func TestMCPServerOverStdio(t *testing.T) {
	h := newHarness(t)
	h.set("demo.api-key", "sk-live-mcp-integration")
	dir := h.project("app", devConfig+"commands:\n  show: probe print API_KEY\n")
	cmd := exec.Command(envruneBin, "mcp")
	cmd.Dir = dir
	cmd.Env = h.environ()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client, err := mcp.NewClient(&mcp.Implementation{Name: "integration"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{Name: "run_command", Arguments: map[string]any{"name": "show"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	if result.IsError || !strings.Contains(string(raw), "API_KEY=****") || strings.Contains(string(raw), "mcp-integration") {
		t.Fatalf("run_command = %s", raw)
	}
}
