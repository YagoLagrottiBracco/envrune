package app

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/envrune/envrune/internal/domain"
	"github.com/envrune/envrune/internal/project"
)

func TestDashboardExposesOnlyMetadataAndRefreshesProjectMappings(t *testing.T) {
	root := t.TempDir()
	vaultPath := filepath.Join(root, "vault.ev1")
	projectPath := filepath.Join(root, "envrune.yml")
	password := []byte("dashboard-test-password")
	secret := []byte("DO-NOT-LEAK-dashboard-plaintext-123")
	service := VaultService{}
	if err := service.Init(vaultPath, password, password); err != nil {
		t.Fatal(err)
	}
	if err := service.Set(vaultPath, password, "openai.personal", secret); err != nil {
		t.Fatal(err)
	}
	config := project.Config{Version: 1, Project: "Example", Environments: map[string]map[string]domain.Reference{"dev": {}}}
	if err := project.WriteAtomic(projectPath, config); err != nil {
		t.Fatal(err)
	}
	if err := service.Link(vaultPath, projectPath, "dev", "API_KEY", "openai.personal", password); err != nil {
		t.Fatal(err)
	}
	dashboard, err := OpenDashboard(vaultPath, password)
	if err != nil {
		t.Fatal(err)
	}
	defer dashboard.Close()
	snapshot := dashboard.Snapshot()
	if len(snapshot.References) != 1 || snapshot.References[0].Name != "openai.personal" || len(snapshot.References[0].Usage) != 1 {
		t.Fatalf("unexpected metadata: %#v", snapshot)
	}
	if len(snapshot.Projects) != 1 || len(snapshot.Projects[0].Environments) != 1 || snapshot.Projects[0].Environments[0].Bindings[0].Variable != "API_KEY" {
		t.Fatal("missing project bindings")
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), string(secret)) || strings.Contains(string(raw), string(password)) {
		t.Fatal("sensitive value exposed in snapshot")
	}
	config.Environments["dev"]["OTHER_KEY"] = domain.Reference("openai.personal")
	if err := project.WriteAtomic(projectPath, config); err != nil {
		t.Fatal(err)
	}
	updated := dashboard.Snapshot()
	if len(updated.References[0].Usage) != 1 || updated.References[0].Usage[0].Variable != "OTHER_KEY" {
		t.Fatal("project metadata was stale")
	}
	dashboard.Close()
	if closed := dashboard.Snapshot(); len(closed.References) != 0 || len(closed.Projects) != 0 {
		t.Fatal("closed dashboard retained metadata")
	}
	if err := service.Set(vaultPath, password, "openai.personal", secret); err != nil {
		t.Fatal("dashboard did not release vault lock:", err)
	}
}
