package app

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/project"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
)

type Level int

const (
	LevelOK Level = iota
	LevelWarn
	LevelError
)

// Finding is one doctor result. Messages hold names, never secret values.
type Finding struct {
	Level   Level
	Message string
}

// StaleAfter is the age after which doctor calls a secret old.
const StaleAfter = 180 * 24 * time.Hour

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`(sk|pk|rk)_(live|test)_[A-Za-z0-9]{10,}`),
	regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`xox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
	regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@`),
}

var longToken = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)

// CheckProject inspects envrune.yml and its directory without the vault.
func CheckProject(projectPath string) []Finding {
	var out []Finding
	config, err := project.Load(projectPath)
	if err != nil {
		return append(out, Finding{LevelError, err.Error()})
	}
	out = append(out, Finding{LevelOK, fmt.Sprintf("envrune.yml is valid (project %s, environments: %s)", config.Project, strings.Join(config.EnvironmentNames(), ", "))})
	for _, problem := range config.Validate() {
		out = append(out, Finding{LevelError, problem})
	}
	out = append(out, scanForValues(projectPath)...)
	out = append(out, findDotenvFiles(filepath.Dir(projectPath))...)
	if path := team.Path(projectPath); team.Exists(path) {
		if members, err := team.Members(path); err != nil {
			out = append(out, Finding{LevelError, fmt.Sprintf("%s is unreadable: %v", team.FileName, err)})
		} else {
			names := make([]string, len(members))
			for i, m := range members {
				names[i] = m.Name
			}
			out = append(out, Finding{LevelOK, fmt.Sprintf("%s is shared with: %s", team.FileName, strings.Join(names, ", "))})
		}
	}
	return out
}

// scanForValues looks for strings in envrune.yml that look like secret
// values. It reports line numbers, never the text.
func scanForValues(projectPath string) []Finding {
	raw, err := os.ReadFile(projectPath)
	if err != nil {
		return nil
	}
	var out []Finding
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		suspicious := false
		for _, pattern := range secretPatterns {
			if pattern.MatchString(text) {
				suspicious = true
				break
			}
		}
		if !suspicious {
			for _, token := range longToken.FindAllString(text, -1) {
				if entropy(token) >= 4.0 {
					suspicious = true
					break
				}
			}
		}
		if suspicious {
			out = append(out, Finding{LevelError, fmt.Sprintf("envrune.yml line %d looks like it contains a secret value; store it with `envrune set` and reference it instead", line)})
		}
	}
	return out
}

func entropy(text string) float64 {
	counts := map[rune]float64{}
	for _, r := range text {
		counts[r]++
	}
	total := float64(len(text))
	var bits float64
	for _, count := range counts {
		p := count / total
		bits -= p * math.Log2(p)
	}
	return bits
}

var dotenvTemplates = map[string]bool{".env.example": true, ".env.sample": true, ".env.template": true, ".env.dist": true}

// findDotenvFiles reports plaintext dotenv files in the project directory and
// its immediate subdirectories.
func findDotenvFiles(root string) []Finding {
	var files []string
	dirs := []string{root}
	if entries, err := os.ReadDir(root); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && entry.Name() != "node_modules" && entry.Name() != "vendor" {
				dirs = append(dirs, filepath.Join(root, entry.Name()))
			}
		}
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.Type().IsRegular() && (name == ".env" || strings.HasPrefix(name, ".env.")) && !dotenvTemplates[name] {
				files = append(files, filepath.Join(dir, name))
			}
		}
	}
	sort.Strings(files)
	var out []Finding
	for _, file := range files {
		rel, _ := filepath.Rel(root, file)
		message := fmt.Sprintf("%s holds plaintext values; import it with `envrune import %s`, then delete it", rel, rel)
		if !gitIgnored(root, rel) {
			message += " (it is not ignored by Git)"
		}
		out = append(out, Finding{LevelWarn, message})
	}
	return out
}

func gitIgnored(dir, rel string) bool {
	cmd := exec.Command("git", "-C", dir, "check-ignore", "-q", rel)
	return cmd.Run() == nil
}

// CheckSecrets checks that every binding of the project resolves and that
// the vault's secrets are current.
func (s *Session) CheckSecrets(projectPath string, now time.Time) []Finding {
	var out []Finding
	config, err := project.Load(projectPath)
	if err == nil {
		for _, environment := range config.EnvironmentNames() {
			resolved, err := s.Resolve(projectPath, environment)
			wipePairs(resolved.Pairs)
			switch {
			case err == nil:
				out = append(out, Finding{LevelOK, fmt.Sprintf("environment %s: all %d references exist", environment, len(config.Environments[environment]))})
			default:
				out = append(out, Finding{LevelError, fmt.Sprintf("environment %s: %v", environment, err)})
			}
		}
	}
	if !s.HasVault() {
		return out
	}
	if has, err := s.HasRecovery(); err == nil && !has {
		out = append(out, Finding{LevelWarn, "the vault has no recovery key; run `envrune recovery reset` and store the key somewhere safe"})
	}
	infos, err := s.Infos()
	if err != nil {
		return append(out, Finding{LevelError, err.Error()})
	}
	for _, info := range infos {
		if info.Expires != "" {
			if expires, err := time.Parse(time.DateOnly, info.Expires); err == nil {
				switch {
				case now.After(expires.Add(24 * time.Hour)):
					out = append(out, Finding{LevelError, fmt.Sprintf("%s expired on %s; rotate it with `envrune rotate %s`", info.Reference, info.Expires, info.Reference)})
				case now.Add(14 * 24 * time.Hour).After(expires):
					out = append(out, Finding{LevelWarn, fmt.Sprintf("%s expires on %s", info.Reference, info.Expires)})
				}
			}
		}
		if !info.UpdatedAt.IsZero() && now.Sub(info.UpdatedAt) > StaleAfter {
			out = append(out, Finding{LevelWarn, fmt.Sprintf("%s has not changed in %d days", info.Reference, int(now.Sub(info.UpdatedAt).Hours()/24))})
		}
	}
	return out
}
