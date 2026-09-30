package paths

import (
	"errors"
	"testing"
)

func TestVaultPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		getenv  func(string) string
		homeDir func() (string, error)
		want    string
		wantErr error
	}{
		{
			name: "uses XDG data home",
			getenv: func(key string) string {
				if key == "XDG_DATA_HOME" {
					return "/tmp/data"
				}
				return ""
			},
			homeDir: func() (string, error) { return "/home/alice", nil },
			want:    "/tmp/data/envrune/vault.ev1",
		},
		{
			name:   "falls back to local share",
			getenv: func(string) string { return "" },
			homeDir: func() (string, error) { return "/home/alice", nil },
			want:    "/home/alice/.local/share/envrune/vault.ev1",
		},
		{
			name:   "returns home directory error",
			getenv: func(string) string { return "" },
			homeDir: func() (string, error) { return "", errors.New("home unavailable") },
			wantErr: errors.New("home unavailable"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VaultPath(tt.getenv, tt.homeDir)
			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Fatalf("VaultPath() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("VaultPath() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("VaultPath() = %q, want %q", got, tt.want)
			}
		})
	}
}
