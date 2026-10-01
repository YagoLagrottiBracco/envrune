package cloud

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// The audit log is a hash chain per organization: every entry stores the
// hash of the one before it, and its own hash covers that and its fields.
// Verifying an export finds an entry that was edited, removed, or inserted
// afterwards. It cannot find a log the server rewrote from the start, so a
// device also remembers the last entry it verified, and an older export can
// be compared with a newer one.

// AuditEntry is one entry as the server returns it and as exports store it,
// one JSON object per line.
type AuditEntry struct {
	ID            int64           `json:"id"`
	OrgID         string          `json:"org_id"`
	At            string          `json:"at"`
	ActorUserID   *string         `json:"actor_user_id"`
	ActorDeviceID *string         `json:"actor_device_id"`
	ActorTokenID  *string         `json:"actor_token_id"`
	Action        string          `json:"action"`
	Target        string          `json:"target"`
	Detail        json.RawMessage `json:"detail"`
	// DetailText is the detail exactly as the database hashed it.
	DetailText string `json:"detail_text"`
	PrevHash   []byte `json:"prev_hash"`
	Hash       []byte `json:"hash"`
}

// AuditHead names the newest entry of a verified log.
type AuditHead struct {
	ID   int64  `json:"id"`
	Hash []byte `json:"hash"`
}

func (h AuditHead) String() string { return fmt.Sprintf("#%d %s", h.ID, hex.EncodeToString(h.Hash)) }

var (
	ErrAuditBroken    = errors.New("the audit log does not verify")
	ErrAuditRewritten = errors.New("the audit log does not continue the one seen before")
)

// hash computes what the database stored for the entry: SHA-256 of the
// previous hash and the fields joined by the unit separator, skipping the
// actors that are absent.
func (e *AuditEntry) hash() ([]byte, error) {
	at, err := time.Parse(time.RFC3339Nano, e.At)
	if err != nil {
		return nil, err
	}
	fields := []string{e.OrgID, at.UTC().Format("2006-01-02T15:04:05.000000Z")}
	for _, actor := range []*string{e.ActorUserID, e.ActorDeviceID, e.ActorTokenID} {
		if actor != nil {
			fields = append(fields, *actor)
		}
	}
	fields = append(fields, e.Action, e.Target, e.DetailText)
	h := sha256.New()
	h.Write(e.PrevHash)
	h.Write([]byte(strings.Join(fields, "\x1f")))
	return h.Sum(nil), nil
}

// VerifyAudit checks a log from its first entry: every hash is the one its
// fields give, every entry continues the one before it, and the readable
// detail is the detail that was hashed. It returns the head.
func VerifyAudit(entries []AuditEntry) (AuditHead, error) {
	if len(entries) == 0 {
		return AuditHead{}, fmt.Errorf("%w: it is empty", ErrAuditBroken)
	}
	var previous *AuditEntry
	for i := range entries {
		e := &entries[i]
		switch {
		case previous == nil && len(e.PrevHash) != 0:
			return AuditHead{}, fmt.Errorf("%w: it does not start at the first entry (#%d follows another)", ErrAuditBroken, e.ID)
		case previous != nil && (e.ID <= previous.ID || e.OrgID != previous.OrgID):
			return AuditHead{}, fmt.Errorf("%w: entry #%d is out of place", ErrAuditBroken, e.ID)
		case previous != nil && !bytes.Equal(e.PrevHash, previous.Hash):
			return AuditHead{}, fmt.Errorf("%w: entry #%d does not follow #%d; something between them was removed or changed", ErrAuditBroken, e.ID, previous.ID)
		}
		want, err := e.hash()
		if err != nil || !bytes.Equal(want, e.Hash) {
			return AuditHead{}, fmt.Errorf("%w: entry #%d was changed", ErrAuditBroken, e.ID)
		}
		var shown, hashed any
		if json.Unmarshal(e.Detail, &shown) != nil || json.Unmarshal([]byte(e.DetailText), &hashed) != nil || !reflect.DeepEqual(shown, hashed) {
			return AuditHead{}, fmt.Errorf("%w: entry #%d shows another detail than the one recorded", ErrAuditBroken, e.ID)
		}
		previous = e
	}
	return AuditHead{ID: previous.ID, Hash: previous.Hash}, nil
}

// AuditContinues checks that newer holds everything older does: the same
// entries, unchanged. Both must already verify.
func AuditContinues(older, newer []AuditEntry) error {
	if len(older) > len(newer) {
		return fmt.Errorf("%w: it has %d entries, fewer than the %d seen before", ErrAuditRewritten, len(newer), len(older))
	}
	for i := range older {
		if older[i].ID != newer[i].ID || !bytes.Equal(older[i].Hash, newer[i].Hash) {
			return fmt.Errorf("%w: entry #%d differs", ErrAuditRewritten, older[i].ID)
		}
	}
	return nil
}

// ReadAudit reads an export: one entry per line.
func ReadAudit(r io.Reader) ([]AuditEntry, error) {
	var entries []AuditEntry
	lines := bufio.NewScanner(r)
	lines.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for lines.Scan() {
		if len(bytes.TrimSpace(lines.Bytes())) == 0 {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal(lines.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("line %d is not an audit entry: %w", len(entries)+1, err)
		}
		entries = append(entries, e)
	}
	return entries, lines.Err()
}

// WriteAudit writes an export that ReadAudit reads back.
func WriteAudit(w io.Writer, entries []AuditEntry) error {
	out := json.NewEncoder(w)
	for i := range entries {
		if err := out.Encode(&entries[i]); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) audit(ctx context.Context, org string, after int64) ([]AuditEntry, error) {
	var out []AuditEntry
	query := url.Values{"after": {strconv.FormatInt(after, 10)}}
	return out, c.call(ctx, http.MethodGet, "/orgs/"+url.PathEscape(org)+"/audit", query, nil, &out)
}

// AuditExport is a verified copy of an organization's audit log.
type AuditExport struct {
	Entries []AuditEntry
	Head    AuditHead
	// Previous is the head this device verified last time, if any; the log
	// was checked to still hold it.
	Previous *AuditHead
}

// Audit downloads an organization's whole audit log and verifies it, and
// checks that it still holds the last entry this device verified before, so
// a server cannot swap the log for another one unnoticed. Owners, admins,
// and auditors may read it.
func (s *Service) Audit(ctx context.Context, org string) (*AuditExport, error) {
	_, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, c, org)
	if err != nil {
		return nil, err
	}
	var entries []AuditEntry
	for after := int64(0); ; {
		page, err := c.audit(ctx, org, after)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 {
			break
		}
		entries = append(entries, page...)
		if last := page[len(page)-1].ID; last > after {
			after = last
		} else {
			return nil, fmt.Errorf("%w: the server sent entries out of order", ErrAuditBroken)
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("the server sent no audit log for %s; only owners, admins, and auditors read it", org)
	}
	head, err := VerifyAudit(entries)
	if err != nil {
		return nil, err
	}
	if entries[0].OrgID != v.trust.OrgID {
		return nil, fmt.Errorf("%w: it belongs to another organization", ErrAuditBroken)
	}
	export := &AuditExport{Entries: entries, Head: head}
	err = s.update(func(st *State) error {
		o := st.org(org)
		if seen := o.AuditHead; seen != nil {
			export.Previous = seen
			found := false
			for i := range entries {
				if entries[i].ID == seen.ID {
					found = bytes.Equal(entries[i].Hash, seen.Hash)
				}
			}
			if !found {
				return fmt.Errorf("%w: entry %s, verified on this device before, is missing or different", ErrAuditRewritten, seen)
			}
		}
		o.AuditHead = &head
		return nil
	})
	if err != nil {
		return nil, err
	}
	return export, nil
}
