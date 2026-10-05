package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// latestReleaseURL answers `version --check` with the newest release.
var latestReleaseURL = "https://api.github.com/repos/YagoLagrottiBracco/envrune/releases/latest"

const releasesPage = "https://github.com/YagoLagrottiBracco/envrune/releases/latest"

// currentVersion is the release this binary was built as: set by the
// release build, or read from the module when installed with `go install`.
// A build from a working tree is "dev".
func currentVersion() string {
	if Version != "dev" {
		return strings.TrimPrefix(Version, "v")
	}
	if info, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(info.Main.Version, "v") && !strings.Contains(info.Main.Version, "-") {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "dev"
}

// executeVersion prints this binary's version. With --check it also asks
// GitHub for the newest release: the only time EnvRune looks for an update,
// and only because it was asked to.
func executeVersion(args []string, stdout io.Writer, status Presenter) int {
	check := len(args) == 1 && args[0] == "--check"
	if len(args) > 1 || len(args) == 1 && !check {
		status.Error("Usage: envrune version [--check]")
		return 2
	}
	current := currentVersion()
	fmt.Fprintf(stdout, "envrune %s\n", current)
	if !check {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	latest, err := latestRelease(ctx)
	if err != nil {
		status.Error("Could not ask for the latest release: " + err.Error() + ".")
		return 1
	}
	switch {
	case current == "dev":
		status.Info("This is a development build. The latest release is " + latest + ".")
	case newerVersion(latest, current):
		status.Warn("EnvRune " + latest + " is available. See " + releasesPage)
	default:
		status.Success("This is the latest release.")
	}
	return 0
}

func latestRelease(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GitHub could not be reached")
	}
	defer resp.Body.Close()
	var release struct {
		Tag string `json:"tag_name"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release) != nil || release.Tag == "" {
		return "", fmt.Errorf("GitHub answered %s", resp.Status)
	}
	return strings.TrimPrefix(release.Tag, "v"), nil
}

// newerVersion reports whether a is a later release than b. Both are
// X.Y.Z; anything else compares as not newer, so a strange tag never nags.
func newerVersion(a, b string) bool {
	x, okA := versionNumbers(a)
	y, okB := versionNumbers(b)
	if !okA || !okB {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return false
}

func versionNumbers(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
