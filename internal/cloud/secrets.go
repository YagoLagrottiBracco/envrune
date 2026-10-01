package cloud

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// Path names a cloud environment, or one secret in it:
// org/project/environment[/name].
type Path struct {
	Org, Project, Env, Name string
}

var (
	slugPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	envPattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,62}$`)
	secretPattern = slugPattern
)

// ParsePath parses org/project/env, or org/project/env/name when withName.
func ParsePath(text string, withName bool) (Path, error) {
	parts := strings.Split(text, "/")
	want, form := 3, "org/project/environment"
	if withName {
		want, form = 4, "org/project/environment/name"
	}
	if len(parts) != want || !slugPattern.MatchString(parts[1]) || !envPattern.MatchString(parts[2]) || parts[0] == "" {
		return Path{}, fmt.Errorf("%q is not %s", text, form)
	}
	p := Path{Org: parts[0], Project: parts[1], Env: parts[2]}
	if withName {
		if !secretPattern.MatchString(parts[3]) {
			return Path{}, fmt.Errorf("%q is not a secret name: use lowercase letters, digits, and dashes", parts[3])
		}
		p.Name = parts[3]
	}
	return p, nil
}

func (p Path) String() string {
	s := p.Org + "/" + p.Project + "/" + p.Env
	if p.Name != "" {
		s += "/" + p.Name
	}
	return s
}

func (p Path) cacheKey() string { return p.Project + "/" + p.Env }

// opened is an environment fetched, verified, and decrypted.
type opened struct {
	payload *EnvPayload
	key     *cloudcrypto.EnvironmentKey
	values  map[string][]byte
}

func (o *opened) wipe() {
	if o.key != nil {
		o.key.Wipe()
	}
	wipeValues(o.values)
}

// fetch downloads an environment, verifies and decrypts it, and, only once
// everything checked out, stores it as the offline cache and records the
// versions seen.
func (s *Service) fetch(ctx context.Context, c *Client, st *State, device *cloudcrypto.Device, v *view, p *projectJSON, e *environmentJSON, allowOlder bool) (*opened, error) {
	payload, err := c.fetchEnvironment(ctx, e.ID, device.DeviceID)
	if err != nil {
		return nil, err
	}
	ver := v.verifier(p, e, payload)
	key, err := ver.key(payload, map[string]age.Identity{device.DeviceID: device.Identity}, st.UserID)
	if err != nil {
		return nil, err
	}
	var values map[string][]byte
	err = s.update(func(fresh *State) error {
		values, err = ver.open(payload, key, fresh.Versions, allowOlder)
		if err != nil {
			return err
		}
		o := fresh.org(v.snap.Slug)
		o.Certificates = mergeCerts(o.Certificates, payload.Certificates)
		o.Cache[Path{Project: p.Slug, Env: e.Slug}.cacheKey()] = &CachedEnv{ProjectID: p.ID, EnvironmentID: e.ID, Payload: payload, FetchedAt: time.Now().UTC()}
		return nil
	})
	if err != nil {
		key.Wipe()
		return nil, err
	}
	return &opened{payload: payload, key: key, values: values}, nil
}

// Pull refreshes the offline cache of an environment and returns the names
// and versions of its secrets.
func (s *Service) Pull(ctx context.Context, path Path, allowOlder bool) ([]SecretInfo, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, path.Org)
	if err != nil {
		return nil, err
	}
	p, e, err := v.environment(path.Project, path.Env)
	if err != nil {
		return nil, err
	}
	o, err := s.fetch(ctx, c, st, device, v, p, e, allowOlder)
	if err != nil {
		return nil, err
	}
	defer o.wipe()
	infos := make([]SecretInfo, 0, len(o.payload.Secrets))
	for _, sec := range o.payload.Secrets {
		infos = append(infos, SecretInfo{Name: sec.Name, Version: sec.Version})
	}
	return infos, nil
}

// Sync pulls every environment this user may use, in every organization.
func (s *Service) Sync(ctx context.Context) ([]Path, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return nil, err
	}
	orgs, err := c.orgs(ctx)
	if err != nil {
		return nil, err
	}
	var synced []Path
	for _, org := range orgs {
		v, err := s.view(ctx, c, org.Slug)
		if err != nil {
			return synced, err
		}
		me, err := v.member(st.UserID)
		if err != nil {
			continue
		}
		for _, p := range v.snap.Projects {
			for _, e := range p.Environments {
				if !me.CanUse(p.Slug, e.Slug) {
					continue
				}
				o, err := s.fetch(ctx, c, st, device, v, &p, &e, false)
				if errors.Is(err, ErrNoKey) {
					continue
				}
				if err != nil {
					return synced, fmt.Errorf("%s/%s/%s: %w", org.Slug, p.Slug, e.Slug, err)
				}
				o.wipe()
				synced = append(synced, Path{Org: org.Slug, Project: p.Slug, Env: e.Slug})
			}
		}
	}
	return synced, nil
}

// Set writes the next version of a secret, encrypted and signed on this
// device. The server accepts only the next version, so a concurrent write
// fails instead of being lost.
func (s *Service) Set(ctx context.Context, path Path, value []byte) (uint64, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return 0, err
	}
	v, err := s.view(ctx, c, path.Org)
	if err != nil {
		return 0, err
	}
	p, e, err := v.environment(path.Project, path.Env)
	if err != nil {
		return 0, err
	}
	me, err := v.member(st.UserID)
	if err != nil {
		return 0, err
	}
	if !me.CanAdminister(p.Slug, e.Slug) {
		return 0, fmt.Errorf("your role (%s) cannot write to %s/%s", me.Role, p.Slug, e.Slug)
	}
	o, err := s.fetch(ctx, c, st, device, v, p, e, false)
	var current uint64
	switch {
	case err == nil:
		defer o.wipe()
		for _, sec := range o.payload.Secrets {
			if sec.Name == path.Name {
				current = sec.Version
			}
		}
	case errors.Is(err, ErrNoKey) && len(e.Secrets) == 0 && e.Epoch == 1:
		// An environment nobody wrote to yet: this device creates its key.
		key, err := s.firstKey(ctx, c, st, device, v, p, e)
		if err != nil {
			return 0, err
		}
		o = &opened{key: key}
		defer o.wipe()
	default:
		return 0, err
	}
	record, err := device.Seal(o.key, path.Name, current+1, value)
	if err != nil {
		return 0, err
	}
	if err := c.putSecretVersion(ctx, e.ID, record); err != nil {
		return 0, err
	}
	if refreshed, err := s.fetch(ctx, c, st, device, v, p, e, false); err == nil {
		refreshed.wipe()
	}
	return record.Version, nil
}

// ReferencePrefix starts the envrune.yml references that name cloud
// secrets, in a project whose envrune.yml links a cloud project.
const ReferencePrefix = "cloud."

// ReferencePath turns a cloud reference into a path: cloud.<name> is a
// secret of the linked project (link, "org/project") in the environment
// being resolved, and cloud.<org>.<project>.<env>.<name> names any secret.
// It reports false for references that are not cloud references.
func ReferencePath(ref, link, environment string) (Path, bool, error) {
	rest, ok := strings.CutPrefix(ref, ReferencePrefix)
	if !ok {
		return Path{}, false, nil
	}
	parts := strings.Split(rest, ".")
	var full string
	switch len(parts) {
	case 1:
		if environment == "" {
			return Path{}, true, fmt.Errorf("%s names a secret of the environment being run; name it in full as cloud.<org>.<project>.<env>.<name> here", ref)
		}
		full = link + "/" + environment + "/" + parts[0]
	case 4:
		full = strings.Join(parts, "/")
	default:
		return Path{}, true, fmt.Errorf("%s is not a cloud reference: use cloud.<name> or cloud.<org>.<project>.<env>.<name>", ref)
	}
	path, err := ParsePath(full, true)
	return path, true, err
}

// Values decrypts an environment from the offline cache, verifying it
// again against the pinned roots. It returns this user's verified role, so
// the caller can apply the consumer limits. The caller wipes the values.
func (s *Service) Values(path Path) (map[string][]byte, string, error) {
	raw, err := s.Store.CloudState()
	if err != nil {
		return nil, "", err
	}
	defer wipe(raw)
	return CachedValues(raw, path)
}

// CachedValues is Values for a state the caller already read, such as a
// session resolving envrune.yml while it holds the vault.
func CachedValues(raw []byte, path Path) (map[string][]byte, string, error) {
	path.Name = ""
	st, err := parseState(raw)
	if err != nil {
		return nil, "", err
	}
	if st.DeviceID == "" {
		return nil, "", ErrNoAccount
	}
	device, err := st.device()
	if err != nil {
		return nil, "", err
	}
	o := st.Orgs[path.Org]
	var cached *CachedEnv
	if o != nil {
		cached = o.Cache[path.cacheKey()]
	}
	if cached == nil || cached.Payload == nil {
		return nil, "", fmt.Errorf("%s is not on this device yet; run `envrune cloud pull %s`", path, path)
	}
	payload := cached.Payload
	ver := &verifier{orgID: o.ID, projectID: cached.ProjectID, envID: cached.EnvironmentID, project: path.Project, env: path.Env,
		trust: cloudcrypto.Trust{OrgID: o.ID, Roots: pinned(o.Roots)}, certs: certificates(o.Certificates, payload.Certificates), devices: payload.Devices}
	me, err := ver.trust.Verify(ver.certs, st.UserID)
	if err != nil || !me.CanUse(path.Project, path.Env) {
		return nil, "", fmt.Errorf("you may not use %s", path)
	}
	// A copy from before a member left holds their signatures, which no
	// longer verify; the removal gave the environment a new epoch to pull.
	stale := func(err error) error {
		if errors.Is(err, ErrSignerLeft) {
			return fmt.Errorf("this device's copy of %s is from before a member who wrote to it left; run `envrune cloud pull %s`", path, path)
		}
		return err
	}
	key, err := ver.key(payload, map[string]age.Identity{device.DeviceID: device.Identity}, st.UserID)
	if err != nil {
		return nil, "", stale(err)
	}
	defer key.Wipe()
	// The cache was checked against the versions seen when it was stored;
	// a newer pull elsewhere moved them forward, which is not a rollback.
	values, err := ver.open(payload, key, nil, true)
	return values, me.Role, stale(err)
}
