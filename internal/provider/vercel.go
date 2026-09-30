package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Vercel reads and writes project environment variables through the Vercel
// REST API, with a token from VERCEL_TOKEN.
type Vercel struct {
	// BaseURL and Client are for tests; empty means the real API.
	BaseURL string
	Client  *http.Client
	Getenv  func(string) string
}

var vercelTargets = []string{"development", "preview", "production"}

func (Vercel) Name() string    { return "vercel" }
func (Vercel) Flags() []string { return []string{"project", "target", "dir"} }

func (v Vercel) Target(environment string, opts Options) string {
	target, _ := vercelTarget(environment, opts)
	project := opts["project"]
	if project == "" {
		project = "the project linked in .vercel/project.json"
	}
	return fmt.Sprintf("Vercel %s variables of %s", target, project)
}

// vercelTarget maps an EnvRune environment to a Vercel one: the same name,
// or --target.
func vercelTarget(environment string, opts Options) (string, error) {
	target := opts["target"]
	if target == "" {
		target = environment
	}
	if !slices.Contains(vercelTargets, target) {
		return "", fmt.Errorf("Vercel has development, preview, and production; choose one with --target")
	}
	return target, nil
}

type vercelProject struct {
	id, team string
}

// project returns the project from --project, or from .vercel/project.json,
// which `vercel link` writes.
func (v Vercel) project(opts Options) (vercelProject, error) {
	if id := opts["project"]; id != "" {
		return vercelProject{id: id, team: opts["team"]}, nil
	}
	dir := opts["dir"]
	if dir == "" {
		dir = "."
	}
	raw, err := os.ReadFile(filepath.Join(dir, ".vercel", "project.json"))
	if err != nil {
		return vercelProject{}, fmt.Errorf("no Vercel project: run `vercel link` here, or pass --project <id or name>")
	}
	var linked struct {
		ProjectID string `json:"projectId"`
		OrgID     string `json:"orgId"`
	}
	if json.Unmarshal(raw, &linked) != nil || linked.ProjectID == "" {
		return vercelProject{}, fmt.Errorf(".vercel/project.json has no projectId; run `vercel link` again")
	}
	p := vercelProject{id: linked.ProjectID}
	if strings.HasPrefix(linked.OrgID, "team_") {
		p.team = linked.OrgID
	}
	return p, nil
}

func (v Vercel) request(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	getenv := v.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	token := getenv("VERCEL_TOKEN")
	if token == "" {
		return errors.New("set VERCEL_TOKEN to a token from https://vercel.com/account/tokens")
	}
	base := v.BaseURL
	if base == "" {
		base = "https://api.vercel.com"
	}
	var reader io.Reader
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
		defer wipe(payload)
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path+"?"+query.Encode(), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach Vercel: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	defer wipe(raw)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		// Error bodies carry a message, never values.
		var failure struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &failure)
		if failure.Error.Message == "" {
			failure.Error.Message = resp.Status
		}
		return fmt.Errorf("Vercel answered %d: %s", resp.StatusCode, failure.Error.Message)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (v Vercel) Pull(ctx context.Context, environment string, opts Options) ([]Value, Notes, error) {
	target, err := vercelTarget(environment, opts)
	if err != nil {
		return nil, nil, err
	}
	project, err := v.project(opts)
	if err != nil {
		return nil, nil, err
	}
	query := url.Values{"decrypt": {"true"}}
	if project.team != "" {
		query.Set("teamId", project.team)
	}
	var list struct {
		Envs []struct {
			Key       string          `json:"key"`
			Value     string          `json:"value"`
			Type      string          `json:"type"`
			Target    json.RawMessage `json:"target"`
			Decrypted bool            `json:"decrypted"`
			GitBranch string          `json:"gitBranch"`
		} `json:"envs"`
	}
	if err := v.request(ctx, http.MethodGet, "/v10/projects/"+url.PathEscape(project.id)+"/env", query, nil, &list); err != nil {
		return nil, nil, err
	}
	var values []Value
	var notes Notes
	for _, env := range list.Envs {
		var targets []string
		if json.Unmarshal(env.Target, &targets) != nil {
			var single string
			if json.Unmarshal(env.Target, &single) == nil {
				targets = []string{single}
			}
		}
		if !slices.Contains(targets, target) || env.GitBranch != "" {
			continue
		}
		switch {
		case env.Type == "sensitive" || env.Type == "secret":
			notes = append(notes, env.Key+" is a sensitive Vercel variable, which cannot be read back")
		case env.Type == "system":
		case env.Type == "encrypted" && !env.Decrypted:
			notes = append(notes, env.Key+" could not be decrypted with this token")
		default:
			values = append(values, Value{Name: env.Key, Value: []byte(env.Value)})
		}
	}
	return values, notes, nil
}

func (v Vercel) Push(ctx context.Context, environment string, values []Value, opts Options) error {
	target, err := vercelTarget(environment, opts)
	if err != nil {
		return err
	}
	project, err := v.project(opts)
	if err != nil {
		return err
	}
	query := url.Values{"upsert": {"true"}}
	if project.team != "" {
		query.Set("teamId", project.team)
	}
	type variable struct {
		Key    string   `json:"key"`
		Value  string   `json:"value"`
		Type   string   `json:"type"`
		Target []string `json:"target"`
	}
	body := make([]variable, len(values))
	for i, value := range values {
		body[i] = variable{Key: value.Name, Value: string(value.Value), Type: "encrypted", Target: []string{target}}
	}
	return v.request(ctx, http.MethodPost, "/v10/projects/"+url.PathEscape(project.id)+"/env", query, body, nil)
}
