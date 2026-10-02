package cloudcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"filippo.io/age"
)

// A sensitive secret never reaches a member's machine. Its value is
// encrypted to the proxy identity of the server, which puts it into the
// member's requests to the hosts its owner allowed. It is the one kind of
// secret the server can read; docs/managed-keys.md says what that costs.

// SensitiveContent is what is encrypted to the proxy identity. It carries
// the allowed hosts and the secret's place next to the value, so nobody
// without the value can make a record that sends it to another host or
// serves it as another secret.
type SensitiveContent struct {
	OrgID         string   `json:"org"`
	ProjectID     string   `json:"project"`
	EnvironmentID string   `json:"environment"`
	Name          string   `json:"name"`
	Version       uint64   `json:"version"`
	Hosts         []string `json:"hosts"`
	Value         []byte   `json:"value"`
	// Certificate and Key, in PEM, are set instead of Value for a service
	// that identifies its callers by a client certificate: the server
	// presents them to the allowed hosts.
	Certificate []byte `json:"certificate,omitempty"`
	Key         []byte `json:"key,omitempty"`
}

// SensitiveRecord is one version of a sensitive secret as the server stores
// it. Hosts and ProxyRecipient are readable copies for people and for
// verification; the server acts on the ones inside Sealed.
type SensitiveRecord struct {
	OrgID, ProjectID, EnvironmentID string
	Name                            string
	Version                         uint64
	Hosts                           []string
	ProxyRecipient                  string
	Sealed                          []byte
	// SealedHash is the SHA-256 of Sealed, which is what the signature
	// covers, so a member's device can verify a record without being sent
	// the ciphertext.
	SealedHash     []byte
	WriterUserID   string
	WriterDeviceID string
	Signature      []byte
}

func (r *SensitiveRecord) signed() []byte {
	hash := r.SealedHash
	if len(r.Sealed) > 0 {
		sum := sha256.Sum256(r.Sealed)
		hash = sum[:]
	}
	return message("envrune-sensitive-v1", str(r.OrgID), str(r.ProjectID), str(r.EnvironmentID), str(r.Name),
		uint64Field(r.Version), str(strings.Join(r.Hosts, "\n")), str(r.ProxyRecipient), hash, str(r.WriterUserID), str(r.WriterDeviceID))
}

var hostPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// NormalizeHosts checks and sorts the hosts a sensitive secret may be sent
// to: full names of servers, reached over HTTPS on the standard port. No
// wildcards and no addresses, so each one names a service on purpose.
func NormalizeHosts(hosts []string) ([]string, error) {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) > 253 || !hostPattern.MatchString(h) {
			return nil, fmt.Errorf("%q is not a host name such as api.example.com: %w", h, ErrMalformed)
		}
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("a sensitive secret needs at least one allowed host: %w", ErrMalformed)
	}
	if len(out) > 16 {
		return nil, fmt.Errorf("a sensitive secret allows at most 16 hosts: %w", ErrMalformed)
	}
	slices.Sort(out)
	return out, nil
}

// SealSensitive encrypts a value to the server's proxy identity, with the
// hosts it may be sent to, and signs the record as this device.
func (d *Device) SealSensitive(orgID, projectID, envID, name string, version uint64, value []byte, hosts []string, proxyRecipient string) (*SensitiveRecord, error) {
	return d.sealSensitive(SensitiveContent{OrgID: orgID, ProjectID: projectID, EnvironmentID: envID, Name: name, Version: version, Value: value}, hosts, proxyRecipient)
}

// SealSensitiveCertificate encrypts a client certificate and its private
// key, both in PEM, to the server's proxy identity, with the hosts they may
// be presented to. The two must belong together.
func (d *Device) SealSensitiveCertificate(orgID, projectID, envID, name string, version uint64, certificate, key []byte, hosts []string, proxyRecipient string) (*SensitiveRecord, error) {
	if _, err := tls.X509KeyPair(certificate, key); err != nil {
		return nil, fmt.Errorf("the certificate and the key are not a pair in PEM: %w", ErrMalformed)
	}
	return d.sealSensitive(SensitiveContent{OrgID: orgID, ProjectID: projectID, EnvironmentID: envID, Name: name, Version: version,
		Certificate: certificate, Key: key}, hosts, proxyRecipient)
}

func (d *Device) sealSensitive(content SensitiveContent, hosts []string, proxyRecipient string) (*SensitiveRecord, error) {
	orgID, projectID, envID, name, version := content.OrgID, content.ProjectID, content.EnvironmentID, content.Name, content.Version
	hosts, err := NormalizeHosts(hosts)
	if err != nil {
		return nil, err
	}
	content.Hosts = hosts
	recipient, err := age.ParseX25519Recipient(proxyRecipient)
	if err != nil {
		return nil, fmt.Errorf("the proxy identity is not valid: %w", ErrMalformed)
	}
	plain, err := json.Marshal(content)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	var sealed bytes.Buffer
	w, err := age.Encrypt(&sealed, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	r := &SensitiveRecord{OrgID: orgID, ProjectID: projectID, EnvironmentID: envID, Name: name, Version: version, Hosts: hosts,
		ProxyRecipient: proxyRecipient, Sealed: sealed.Bytes(), WriterUserID: d.UserID, WriterDeviceID: d.DeviceID}
	sum := sha256.Sum256(r.Sealed)
	r.SealedHash = sum[:]
	r.Signature = d.sign(r.signed())
	return r, nil
}

// Verify checks that the record was written by the device whose signing key
// the caller verified. It says who marked the secret and which hosts they
// allowed; it does not open the value, which no device can.
func (r *SensitiveRecord) Verify(writerKey ed25519.PublicKey) error {
	return verify(writerKey, r.signed(), r.Signature)
}

// OpenSensitive decrypts a record with the proxy identity and checks that
// its content is the one for that place. Only the server does this in
// production (in cloud/web); here it serves tests and tools.
func OpenSensitive(r *SensitiveRecord, identity age.Identity) (*SensitiveContent, error) {
	reader, err := age.Decrypt(bytes.NewReader(r.Sealed), identity)
	if err != nil {
		return nil, ErrDecrypt
	}
	plain, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	defer wipe(plain)
	if err != nil {
		return nil, ErrDecrypt
	}
	var c SensitiveContent
	if json.Unmarshal(plain, &c) != nil {
		return nil, ErrMalformed
	}
	if c.OrgID != r.OrgID || c.ProjectID != r.ProjectID || c.EnvironmentID != r.EnvironmentID || c.Name != r.Name || c.Version != r.Version {
		wipe(c.Value)
		return nil, fmt.Errorf("%w: the content belongs to another secret or version", ErrDecrypt)
	}
	return &c, nil
}

// ProxyFingerprint is what a member compares before trusting a server's
// proxy identity with a value.
func ProxyFingerprint(recipient string) string { return Fingerprint(str("proxy"), str(recipient)) }
