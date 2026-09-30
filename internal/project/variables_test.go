package project

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadString(t *testing.T, data string) (Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "envrune.yml")
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestVariablesKeepOrderAndDefaults(t *testing.T) {
	config, err := loadString(t, `version: 1
project: shop
variables:
  DATABASE_URL:
    description: Postgres for the app
    how_to_get: Run make db
    type: url
    format: ^postgres(ql)?://
  PORT:
    type: int
    required: false
  FEATURE_X:
environments:
  development: {}
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Variables) != 3 || config.Variables[0].Name != "DATABASE_URL" || config.Variables[2].Name != "FEATURE_X" {
		t.Fatalf("Variables = %+v", config.Variables)
	}
	db, _ := config.Variable("DATABASE_URL")
	port, _ := config.Variable("PORT")
	feature, _ := config.Variable("FEATURE_X")
	if !db.Required || port.Required || !feature.Required || db.HowToGet != "Run make db" {
		t.Fatalf("defaults wrong: %+v %+v %+v", db, port, feature)
	}
}

func TestVariablesRejectMistakes(t *testing.T) {
	for _, section := range []string{
		"variables:\n  bad-name: {}\n",
		"variables:\n  A:\n    type: number\n",
		"variables:\n  A:\n    format: '(['\n",
		"variables:\n  A:\n    required: maybe\n",
		"variables:\n  A:\n    secret: x\n",
	} {
		if _, err := loadString(t, "version: 1\nproject: x\n"+section+"environments: {}\n"); err == nil {
			t.Fatalf("Load accepted %q", section)
		}
	}
}

func TestVariableCheckExplainsWithoutTheValue(t *testing.T) {
	cases := []struct {
		v     Variable
		value string
		ok    bool
	}{
		{Variable{Type: "url"}, "postgres://u:p@db:5432/app", true},
		{Variable{Type: "url"}, "localhost:5432", false},
		{Variable{Type: "int"}, "8080", true},
		{Variable{Type: "int"}, "80a", false},
		{Variable{Type: "bool"}, "Yes", true},
		{Variable{Type: "bool"}, "maybe", false},
		{Variable{Format: "^sk_(test|live)_"}, "sk_test_123", true},
		{Variable{Format: "^sk_(test|live)_"}, "pk_test_secret-value", false},
	}
	for _, c := range cases {
		reason := c.v.Check([]byte(c.value))
		if (reason == "") != c.ok || strings.Contains(reason, c.value) {
			t.Fatalf("Check(%+v, %q) = %q", c.v, c.value, reason)
		}
	}
}
