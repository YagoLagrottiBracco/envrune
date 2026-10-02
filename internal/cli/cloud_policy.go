package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
)

const cloudPolicyUsage = "cloud policy show <org> | set <org> <file> | clear <org>"

// cloudPolicy shows and replaces an organization's rules about which roles
// may fetch which environments (docs/cloud-operations.md).
func (w Workspace) cloudPolicy(argv []string) int {
	ctx, cancel := cloudContext()
	defer cancel()
	s := w.cloudService()
	switch {
	case len(argv) == 2 && argv[0] == "show":
		rules, err := s.Policy(ctx, argv[1])
		if err != nil {
			return w.cloudFail(err)
		}
		if len(rules) == 0 {
			w.status().Info(argv[1] + " has no rules: a member's role and scope decide what they may fetch.")
			return 0
		}
		out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(out, "ENVIRONMENTS\tDENIED TO")
		for _, r := range rules {
			fmt.Fprintf(out, "%s\t%s\n", r.Environments, strings.Join(r.Deny, ", "))
		}
		out.Flush()
		w.status().Info("Rules never apply to owners or to machine tokens.")
		return 0
	case len(argv) == 3 && argv[0] == "set":
		raw, err := os.ReadFile(argv[2])
		if err != nil {
			return w.fail(err, "The file could not be read.")
		}
		var file struct {
			Rules []cloud.PolicyRule `yaml:"rules"`
		}
		decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
		decoder.KnownFields(true)
		if err := decoder.Decode(&file); err != nil {
			w.status().Error("The file is not a list of rules: it has one key, rules, whose entries have environments and deny.")
			return 1
		}
		if err := s.SetPolicy(ctx, argv[1], file.Rules); err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("%s now has %d %s.", argv[1], len(file.Rules), plural(len(file.Rules), "rule", "rules")))
		w.status().Info("A member a rule denies is refused from now on. Keys their device already holds are replaced when the environment gets a new one: `envrune cloud rotate`.")
		return 0
	case len(argv) == 2 && argv[0] == "clear":
		if err := s.SetPolicy(ctx, argv[1], nil); err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(argv[1] + " has no rules now.")
		w.status().Info("Members who were denied get their keys with `envrune cloud share " + argv[1] + "`.")
		return 0
	}
	return w.usageError(cloudPolicyUsage)
}
