package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// An organization may deny roles an environment, whatever scope a member
// was given (docs/cloud-operations.md). The server enforces the rules where
// it serves ciphertext and keys. Devices read them to leave denied members
// out when they wrap a key, which the server would refuse, and to say why
// an environment is not theirs to fetch. Rules are not signed: they only
// take access away, which a server can always do by refusing.

// PolicyRule denies roles the environments it names.
type PolicyRule struct {
	// Environments is "project/environment"; either side may be "*".
	Environments string   `json:"environments" yaml:"environments"`
	Deny         []string `json:"deny" yaml:"deny"`
}

// deniable are the roles a rule may name. Owners keep every environment
// manageable, and machine tokens have scopes of their own.
var deniable = []string{cloudcrypto.RoleAdmin, cloudcrypto.RoleMaintainer, cloudcrypto.RoleConsumer}

func (r PolicyRule) matches(project, env string) bool {
	p, e, ok := strings.Cut(r.Environments, "/")
	return ok && (p == "*" || p == project) && (e == "*" || e == env)
}

// CheckPolicy reports the first mistake in rules, as the server would.
func CheckPolicy(rules []PolicyRule) error {
	if len(rules) > 100 {
		return fmt.Errorf("an organization has at most 100 rules")
	}
	for i, r := range rules {
		p, e, ok := strings.Cut(r.Environments, "/")
		if !ok || !(p == "*" || slugPattern.MatchString(p)) || !(e == "*" || envPattern.MatchString(e)) {
			return fmt.Errorf("rule %d: environments is project/environment, where either side may be *; %q is not", i+1, r.Environments)
		}
		if len(r.Deny) == 0 {
			return fmt.Errorf("rule %d denies no role", i+1)
		}
		for _, role := range r.Deny {
			if !slices.Contains(deniable, role) {
				return fmt.Errorf("rule %d: a rule can deny %s; %q is not one of them", i+1, strings.Join(deniable, ", "), role)
			}
		}
	}
	return nil
}

// denied reports whether the organization's rules deny a member of role
// the environment.
func (v *view) denied(m cloudcrypto.Membership, project, env string) bool {
	if m.Role == cloudcrypto.RoleOwner {
		return false
	}
	return slices.ContainsFunc(v.snap.Policy, func(r PolicyRule) bool { return r.matches(project, env) && slices.Contains(r.Deny, m.Role) })
}

// Policy returns an organization's rules.
func (s *Service) Policy(ctx context.Context, org string) ([]PolicyRule, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return nil, err
	}
	return v.snap.Policy, nil
}

// SetPolicy replaces an organization's rules. Only an owner may.
func (s *Service) SetPolicy(ctx context.Context, org string, rules []PolicyRule) error {
	_, c, err := s.signedIn()
	if err != nil {
		return err
	}
	if err := CheckPolicy(rules); err != nil {
		return err
	}
	if rules == nil {
		rules = []PolicyRule{}
	}
	return c.call(ctx, http.MethodPut, "/orgs/"+url.PathEscape(org)+"/policy", nil, map[string]any{"rules": rules}, nil)
}
