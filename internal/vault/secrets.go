package vault

import (
	"bytes"
	"sort"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
)

// maxHistory is how many replaced values each secret keeps for rollback.
const maxHistory = 5

type payload struct {
	Version  uint8                  `json:"version"`
	Secrets  map[string][]byte      `json:"secrets"`
	Projects []string               `json:"projects"`
	Meta     map[string]*SecretMeta `json:"meta,omitempty"`
	// Identity is the X25519 private key that opens shared team files.
	Identity []byte `json:"identity,omitempty"`
}

// SecretMeta describes one secret. History holds earlier values, newest
// first, so they stay encrypted with the rest of the vault.
type SecretMeta struct {
	Description string      `json:"description,omitempty"`
	Owner       string      `json:"owner,omitempty"`
	Expires     string      `json:"expires,omitempty"` // YYYY-MM-DD
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	History     []PastValue `json:"history,omitempty"`
}

type PastValue struct {
	Value      []byte    `json:"value"`
	ReplacedAt time.Time `json:"replaced_at"`
}

// Info is the value-free view of a secret's metadata.
type Info struct {
	Reference   domain.Reference
	Description string
	Owner       string
	Expires     string
	CreatedAt   time.Time // zero when the secret predates metadata
	UpdatedAt   time.Time
	Previous    []time.Time // when each kept earlier value was replaced
}

func newPayload() payload {
	return payload{Version: 1, Secrets: map[string][]byte{}, Projects: []string{}, Meta: map[string]*SecretMeta{}}
}

func (p *payload) wipe() {
	for _, value := range p.Secrets {
		wipe(value)
	}
	for _, meta := range p.Meta {
		for _, past := range meta.History {
			wipe(past.Value)
		}
	}
	wipe(p.Identity)
	clear(p.Secrets)
	clear(p.Meta)
}

func (p *payload) meta(key string) *SecretMeta {
	if p.Meta == nil {
		p.Meta = map[string]*SecretMeta{}
	}
	m := p.Meta[key]
	if m == nil {
		m = &SecretMeta{}
		p.Meta[key] = m
	}
	return m
}

func (v *Opened) RegisterProject(path string) {
	for _, known := range v.data.Projects {
		if known == path {
			return
		}
	}
	v.data.Projects = append(v.data.Projects, path)
}

func (v *Opened) Projects() []string { return append([]string(nil), v.data.Projects...) }

// Put stores value. A different earlier value is kept in the history.
func (v *Opened) Put(ref domain.Reference, value []byte, now time.Time) error {
	key := ref.String()
	m := v.data.meta(key)
	old, exists := v.data.Secrets[key]
	switch {
	case !exists:
		if m.CreatedAt.IsZero() {
			m.CreatedAt = now
		}
	case bytes.Equal(old, value):
		wipe(old)
	default:
		m.History = append([]PastValue{{Value: old, ReplacedAt: now}}, m.History...)
		for _, dropped := range m.History[min(len(m.History), maxHistory):] {
			wipe(dropped.Value)
		}
		m.History = m.History[:min(len(m.History), maxHistory)]
	}
	m.UpdatedAt = now
	v.data.Secrets[key] = append([]byte(nil), value...)
	return nil
}

func (v *Opened) Value(ref domain.Reference) ([]byte, bool) {
	value, ok := v.data.Secrets[ref.String()]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), value...), true
}

func (v *Opened) Has(ref domain.Reference) bool {
	_, ok := v.data.Secrets[ref.String()]
	return ok
}

func (v *Opened) References() []domain.Reference {
	refs := make([]domain.Reference, 0, len(v.data.Secrets))
	for raw := range v.data.Secrets {
		if ref, err := domain.ParseReference(raw); err == nil {
			refs = append(refs, ref)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })
	return refs
}

func (v *Opened) Info(ref domain.Reference) (Info, bool) {
	if !v.Has(ref) {
		return Info{}, false
	}
	info := Info{Reference: ref}
	if m := v.data.Meta[ref.String()]; m != nil {
		info.Description, info.Owner, info.Expires = m.Description, m.Owner, m.Expires
		info.CreatedAt, info.UpdatedAt = m.CreatedAt, m.UpdatedAt
		for _, past := range m.History {
			info.Previous = append(info.Previous, past.ReplacedAt)
		}
	}
	return info, true
}

// MetaChange sets only the fields that are not nil.
type MetaChange struct {
	Description, Owner, Expires *string
}

func (v *Opened) SetMeta(ref domain.Reference, change MetaChange) error {
	if !v.Has(ref) {
		return ErrUnknownReference
	}
	m := v.data.meta(ref.String())
	if change.Description != nil {
		m.Description = *change.Description
	}
	if change.Owner != nil {
		m.Owner = *change.Owner
	}
	if change.Expires != nil {
		m.Expires = *change.Expires
	}
	return nil
}

// Rollback swaps the current value with the most recent earlier one, so a
// second rollback undoes the first.
func (v *Opened) Rollback(ref domain.Reference, now time.Time) error {
	key := ref.String()
	m := v.data.Meta[key]
	current, exists := v.data.Secrets[key]
	if !exists {
		return ErrUnknownReference
	}
	if m == nil || len(m.History) == 0 {
		return ErrNoHistory
	}
	v.data.Secrets[key] = m.History[0].Value
	m.History[0] = PastValue{Value: current, ReplacedAt: now}
	m.UpdatedAt = now
	return nil
}

func (v *Opened) Remove(ref domain.Reference) error {
	key := ref.String()
	value, exists := v.data.Secrets[key]
	if !exists {
		return ErrUnknownReference
	}
	wipe(value)
	delete(v.data.Secrets, key)
	if m := v.data.Meta[key]; m != nil {
		for _, past := range m.History {
			wipe(past.Value)
		}
		delete(v.data.Meta, key)
	}
	return nil
}

func (v *Opened) Identity() []byte { return append([]byte(nil), v.data.Identity...) }

func (v *Opened) SetIdentity(identity []byte) {
	wipe(v.data.Identity)
	v.data.Identity = append([]byte(nil), identity...)
}
