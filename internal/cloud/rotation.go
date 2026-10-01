package cloud

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Guided rotation. When a member is removed or a machine token revoked, the
// server lists every secret they could read. A new epoch keeps them from
// reading what is written next; only a new value protects what they already
// knew. Each listed secret stays pending until someone writes a new value,
// or accepts on the record that it stays as it is.

const (
	RotationPending  = "pending"
	RotationRotated  = "rotated"
	RotationAccepted = "accepted"
)

// RotationTask is one departure and the secrets it exposed.
type RotationTask struct {
	ID      string
	Reason  string
	Subject string // the user id, or "token <id>"
	Created time.Time
	Items   []RotationItem
}

type RotationItem struct {
	Path   Path
	Status string
}

// Pending counts the secrets still waiting for a new value.
func (t RotationTask) Pending() int {
	n := 0
	for _, i := range t.Items {
		if i.Status == RotationPending {
			n++
		}
	}
	return n
}

// secretPaths names the organization's secrets by id.
func (s *Snapshot) secretPaths() map[string]Path {
	paths := map[string]Path{}
	for _, p := range s.Projects {
		for _, e := range p.Environments {
			for _, sec := range e.Secrets {
				paths[sec.ID] = Path{Org: s.Slug, Project: p.Slug, Env: e.Slug, Name: sec.Name}
			}
		}
	}
	return paths
}

// Rotation lists an organization's guided rotations, oldest first. The list
// is the server's word: it could hide a task, as it could hide a member.
func (s *Service) Rotation(ctx context.Context, org string) ([]RotationTask, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return nil, err
	}
	paths := v.snap.secretPaths()
	tasks := make([]RotationTask, 0, len(v.snap.Rotation))
	for _, r := range v.snap.Rotation {
		task := RotationTask{ID: r.ID, Reason: r.Reason}
		switch {
		case r.SubjectUserID != nil:
			task.Subject = *r.SubjectUserID
		case r.SubjectToken != nil:
			task.Subject = "token " + *r.SubjectToken
		}
		task.Created, _ = time.Parse(time.RFC3339Nano, r.CreatedAt)
		for _, i := range r.Items {
			if path, ok := paths[i.SecretID]; ok {
				task.Items = append(task.Items, RotationItem{Path: path, Status: i.Status})
			}
		}
		slices.SortFunc(task.Items, func(a, b RotationItem) int { return strings.Compare(a.Path.String(), b.Path.String()) })
		tasks = append(tasks, task)
	}
	slices.SortStableFunc(tasks, func(a, b RotationTask) int { return a.Created.Compare(b.Created) })
	return tasks, nil
}

// AcceptRotation records that a secret someone who left could read keeps its
// value, in every rotation that still waits for it. It returns how many.
func (s *Service) AcceptRotation(ctx context.Context, path Path) (int, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return 0, err
	}
	v, err := s.view(ctx, c, path.Org)
	if err != nil {
		return 0, err
	}
	var id string
	for secret, p := range v.snap.secretPaths() {
		if p == path {
			id = secret
		}
	}
	if id == "" {
		return 0, fmt.Errorf("no secret %s", path)
	}
	accepted := 0
	for _, r := range v.snap.Rotation {
		for _, i := range r.Items {
			if i.SecretID != id || i.Status != RotationPending {
				continue
			}
			if err := c.updateRotationItem(ctx, r.ID, id, RotationAccepted); err != nil {
				return accepted, err
			}
			accepted++
		}
	}
	if accepted == 0 {
		return 0, fmt.Errorf("%s is not waiting for rotation", path)
	}
	return accepted, nil
}
