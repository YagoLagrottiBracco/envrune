package project

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Variable documents one environment variable under variables: in
// envrune.yml: what it is for, how a new developer gets a value, and what a
// valid value looks like. It never holds a value.
type Variable struct {
	Name        string
	Description string
	HowToGet    string
	Type        string // string, url, int, or bool; empty means string
	Format      string // a regular expression the value must match
	Required    bool   // true unless required: false
	format      *regexp.Regexp
}

var variableTypes = map[string]bool{"": true, "string": true, "url": true, "int": true, "bool": true}

func parseVariables(node *yaml.Node) ([]Variable, error) {
	pairs, err := mappingPairs(node, "variables")
	if err != nil {
		return nil, err
	}
	var out []Variable
	for _, pair := range pairs {
		name, value := pair[0].Value, pair[1]
		if !variableName.MatchString(name) {
			return nil, configError(pair[0], "%q is not a valid variable name; use uppercase letters, digits, and _", name)
		}
		v := Variable{Name: name, Required: true}
		if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
			out = append(out, v)
			continue
		}
		fields, err := mappingPairs(value, "variables."+name)
		if err != nil {
			return nil, configError(value, "variables.%s must be a mapping with description, how_to_get, type, format, and required", name)
		}
		for _, field := range fields {
			key, node := field[0].Value, field[1]
			if key == "required" {
				if node.Kind != yaml.ScalarNode || node.Tag != "!!bool" {
					return nil, configError(node, "variables.%s.required must be true or false", name)
				}
				v.Required = node.Value == "true"
				continue
			}
			text, err := stringValue(node, "variables."+name+"."+key)
			if err != nil {
				return nil, err
			}
			switch key {
			case "description":
				v.Description = text
			case "how_to_get":
				v.HowToGet = text
			case "type":
				if !variableTypes[text] {
					return nil, configError(node, "variables.%s.type must be string, url, int, or bool", name)
				}
				v.Type = text
			case "format":
				if v.format, err = regexp.Compile(text); err != nil {
					return nil, configError(node, "variables.%s.format is not a valid regular expression", name)
				}
				v.Format = text
			default:
				return nil, configError(field[0], "variables.%s has unknown key %q", name, key)
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// Check reports why value is not valid for the variable, or "" when it is.
// The reason never contains the value.
func (v Variable) Check(value []byte) string {
	switch v.Type {
	case "url":
		u, err := url.Parse(string(value))
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "is not a URL with a scheme and a host"
		}
	case "int":
		if _, err := strconv.ParseInt(string(value), 10, 64); err != nil {
			return "is not a whole number"
		}
	case "bool":
		switch strings.ToLower(string(value)) {
		case "true", "false", "1", "0", "yes", "no":
		default:
			return "is not true or false"
		}
	}
	if v.Format != "" {
		format := v.format
		if format == nil {
			format = regexp.MustCompile(v.Format)
		}
		if !format.Match(value) {
			return "does not match the format " + v.Format
		}
	}
	return ""
}

// Variable returns the documentation of a variable, if envrune.yml has it.
func (c Config) Variable(name string) (Variable, bool) {
	for _, v := range c.Variables {
		if v.Name == name {
			return v, true
		}
	}
	return Variable{}, false
}
