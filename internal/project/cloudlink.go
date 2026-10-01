package project

import (
	"bytes"
	"os"

	"gopkg.in/yaml.v3"
)

// SetCloud links envrune.yml to an EnvRune Cloud project, "org/project".
// Like SetBinding, it edits the YAML tree in place, so comments, key order,
// and the other sections are kept.
func SetCloud(path, link string) error {
	if !cloudLink.MatchString(link) {
		return ErrInvalidConfig
	}
	lock, err := lockConfig(path)
	if err != nil {
		return err
	}
	defer lock.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		return ErrInvalidConfig
	}
	var doc yaml.Node
	if yaml.Unmarshal(raw, &doc) != nil || len(doc.Content) != 1 {
		return &ConfigError{Message: "not valid YAML"}
	}
	root := doc.Content[0]
	if _, err := parseDocument(root); err != nil {
		return err
	}
	if existing := childValue(root, "cloud"); existing != nil {
		existing.Value, existing.Tag, existing.Style = link, "!!str", 0
	} else {
		// After project:, where the file introduces itself.
		at := len(root.Content)
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "project" {
				at = i + 2
			}
		}
		pair := []*yaml.Node{scalar("cloud"), scalar(link)}
		root.Content = append(root.Content[:at], append(pair, root.Content[at:]...)...)
	}
	var out bytes.Buffer
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if encoder.Encode(&doc) != nil || encoder.Close() != nil {
		return ErrInvalidConfig
	}
	return writeFile(path, out.Bytes())
}
