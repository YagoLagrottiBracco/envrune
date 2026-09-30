package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// OnePassword reads the fields of a 1Password item through the 1Password
// CLI. It does not push: `op item create` and `op item edit` take values as
// command-line arguments, which other processes can read.
type OnePassword struct{}

func (OnePassword) Name() string    { return "1password" }
func (OnePassword) Flags() []string { return []string{"item", "vault"} }

func (OnePassword) Target(_ string, opts Options) string {
	target := "1Password item " + opts["item"]
	if vault := opts["vault"]; vault != "" {
		target += " in vault " + vault
	}
	return target
}

var notNameCharacter = regexp.MustCompile(`[^A-Z0-9_]+`)

// variableName turns a field label into a variable name: "Stripe key"
// becomes STRIPE_KEY.
func variableName(label string) string {
	name := strings.Trim(notNameCharacter.ReplaceAllString(strings.ToUpper(strings.TrimSpace(label)), "_"), "_")
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}
	return name
}

func (OnePassword) Pull(ctx context.Context, _ string, opts Options) ([]Value, Notes, error) {
	item := opts["item"]
	if item == "" {
		return nil, nil, errors.New("name the item with --item")
	}
	if _, err := lookPath("op"); err != nil {
		return nil, nil, errors.New("the 1Password CLI (op) is required: install it and sign in with `op signin`")
	}
	args := []string{"item", "get", item, "--format", "json", "--reveal"}
	if vault := opts["vault"]; vault != "" {
		args = append(args, "--vault", vault)
	}
	cmd := execCommand(ctx, "op", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	defer wipe(stdout.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("op could not read %s: %s", item, strings.TrimSpace(stderr.String()))
	}
	var parsed struct {
		Fields []struct {
			Label   string `json:"label"`
			Value   string `json:"value"`
			Purpose string `json:"purpose"`
			Type    string `json:"type"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return nil, nil, fmt.Errorf("op printed something that is not an item: %w", err)
	}
	var values []Value
	var notes Notes
	seen := map[string]bool{}
	for _, field := range parsed.Fields {
		if field.Value == "" || field.Purpose == "NOTES" {
			continue
		}
		name := variableName(field.Label)
		switch {
		case name == "":
			notes = append(notes, fmt.Sprintf("a field labeled %q has no usable variable name", field.Label))
		case seen[name]:
			notes = append(notes, fmt.Sprintf("more than one field becomes %s; only the first was used", name))
		default:
			seen[name] = true
			values = append(values, Value{Name: name, Value: []byte(field.Value)})
		}
	}
	return values, notes, nil
}
