// Package team keeps secrets shared by a team in a file that can be
// committed next to envrune.yml. The file is encrypted to each member's
// X25519 public key, in the style of age and sops, so no server is needed:
// adding or removing a member re-encrypts the file for the new member list.
package team

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	crypto "github.com/YagoLagrottiBracco/envrune/internal/crypto"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
)

// FileName is the shared file that lives next to envrune.yml.
const FileName = "envrune.team.json"

// Prefix marks references that resolve from the team file instead of the
// personal vault.
const Prefix = "team."

const (
	publicPrefix  = "envrune-pub-"
	privatePrefix = "envrune-key-"
	kdfInfo       = "envrune team file v1"
)

var (
	ErrNotRecipient    = errors.New("this identity is not a recipient of the team file")
	ErrInvalidKey      = errors.New("invalid team key")
	ErrInvalidFile     = errors.New("invalid team file")
	ErrUnknownMember   = errors.New("no team member has that name")
	ErrDuplicateMember = errors.New("a team member already has that name or key")
	ErrLastMember      = errors.New("the team file needs at least one member")
	ErrNotTeamRef      = errors.New(`team references must start with "team."`)
	ErrUnknownRef      = errors.New("the team file has no such reference")
)

var encoding = base64.RawURLEncoding

// Member is someone who can open the team file.
type Member struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type wrappedKey struct {
	PublicKey string `json:"public_key"`
	Ephemeral string `json:"ephemeral"`
	Nonce     string `json:"nonce"`
	Wrapped   string `json:"wrapped"`
}

type fileFormat struct {
	Version    int          `json:"version"`
	Members    []Member     `json:"members"`
	Keys       []wrappedKey `json:"keys"`
	Nonce      string       `json:"nonce"`
	Ciphertext string       `json:"ciphertext"`
}

// NewIdentity returns a new private key in its text form.
func NewIdentity() (string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	return privatePrefix + encoding.EncodeToString(key.Bytes()), nil
}

func parsePrivate(identity string) (*ecdh.PrivateKey, error) {
	raw, err := encoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(identity), privatePrefix))
	if err != nil || !strings.HasPrefix(strings.TrimSpace(identity), privatePrefix) {
		return nil, ErrInvalidKey
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return key, nil
}

func parsePublic(text string) (*ecdh.PublicKey, error) {
	if !strings.HasPrefix(text, publicPrefix) {
		return nil, ErrInvalidKey
	}
	raw, err := encoding.DecodeString(strings.TrimPrefix(text, publicPrefix))
	if err != nil {
		return nil, ErrInvalidKey
	}
	key, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, ErrInvalidKey
	}
	return key, nil
}

func formatPublic(key *ecdh.PublicKey) string {
	return publicPrefix + encoding.EncodeToString(key.Bytes())
}

// PublicKey returns the shareable public key of identity.
func PublicKey(identity string) (string, error) {
	key, err := parsePrivate(identity)
	if err != nil {
		return "", err
	}
	return formatPublic(key.PublicKey()), nil
}

// ValidPublicKey reports whether text is a public key made by Envrune.
func ValidPublicKey(text string) bool {
	_, err := parsePublic(text)
	return err == nil
}

// File is an opened team file.
type File struct {
	path    string
	members []Member
	secrets map[string][]byte
}

// Path returns the team file that belongs to the project at projectPath.
func Path(projectPath string) string { return filepath.Join(filepath.Dir(projectPath), FileName) }

// Exists reports whether a team file is present at path.
func Exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// Create starts a team file whose only member is the owner of identity.
func Create(path, name, identity string) (*File, error) {
	public, err := PublicKey(identity)
	if err != nil {
		return nil, err
	}
	if !validName(name) {
		return nil, ErrInvalidFile
	}
	f := &File{path: path, members: []Member{{Name: name, PublicKey: public}}, secrets: map[string][]byte{}}
	return f, f.Save()
}

// Members reads the member list without decrypting anything.
func Members(path string) ([]Member, error) {
	format, err := readFormat(path)
	if err != nil {
		return nil, err
	}
	return format.Members, nil
}

func readFormat(path string) (fileFormat, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fileFormat{}, err
	}
	var format fileFormat
	if json.Unmarshal(raw, &format) != nil || format.Version != 1 || len(format.Members) == 0 {
		return fileFormat{}, ErrInvalidFile
	}
	return format, nil
}

// Open decrypts the team file with identity.
func Open(path, identity string) (*File, error) {
	format, err := readFormat(path)
	if err != nil {
		return nil, err
	}
	private, err := parsePrivate(identity)
	if err != nil {
		return nil, err
	}
	public := formatPublic(private.PublicKey())
	for _, wrapped := range format.Keys {
		if wrapped.PublicKey != public {
			continue
		}
		fileKey, err := unwrapFileKey(private, wrapped)
		if err != nil {
			return nil, ErrInvalidFile
		}
		defer wipe(fileKey)
		nonce, err1 := encoding.DecodeString(format.Nonce)
		ciphertext, err2 := encoding.DecodeString(format.Ciphertext)
		if err1 != nil || err2 != nil {
			return nil, ErrInvalidFile
		}
		plain, err := crypto.Open(fileKey, nonce, ciphertext, membersAAD(format.Members))
		if err != nil {
			return nil, ErrInvalidFile
		}
		defer wipe(plain)
		secrets := map[string][]byte{}
		if json.Unmarshal(plain, &secrets) != nil {
			return nil, ErrInvalidFile
		}
		return &File{path: path, members: format.Members, secrets: secrets}, nil
	}
	return nil, ErrNotRecipient
}

// membersAAD binds the ciphertext to the member list, so a member cannot be
// added or removed without re-encrypting.
func membersAAD(members []Member) []byte {
	keys := make([]string, len(members))
	for i, m := range members {
		keys[i] = m.Name + "=" + m.PublicKey
	}
	sort.Strings(keys)
	return []byte(kdfInfo + "\n" + strings.Join(keys, "\n"))
}

func deriveWrapKey(shared, ephemeral, recipient []byte) ([]byte, error) {
	salt := append(append([]byte(nil), ephemeral...), recipient...)
	return hkdf.Key(sha256.New, shared, salt, kdfInfo, 32)
}

func wrapFileKey(fileKey []byte, recipient *ecdh.PublicKey) (wrappedKey, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return wrappedKey{}, err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return wrappedKey{}, err
	}
	kek, err := deriveWrapKey(shared, ephemeral.PublicKey().Bytes(), recipient.Bytes())
	wipe(shared)
	if err != nil {
		return wrappedKey{}, err
	}
	defer wipe(kek)
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return wrappedKey{}, err
	}
	sealed, err := crypto.Seal(kek, nonce, fileKey, recipient.Bytes())
	if err != nil {
		return wrappedKey{}, err
	}
	return wrappedKey{
		PublicKey: formatPublic(recipient),
		Ephemeral: encoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Nonce:     encoding.EncodeToString(nonce),
		Wrapped:   encoding.EncodeToString(sealed),
	}, nil
}

func unwrapFileKey(private *ecdh.PrivateKey, wrapped wrappedKey) ([]byte, error) {
	ephemeralRaw, err := encoding.DecodeString(wrapped.Ephemeral)
	if err != nil {
		return nil, err
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(ephemeralRaw)
	if err != nil {
		return nil, err
	}
	nonce, err1 := encoding.DecodeString(wrapped.Nonce)
	sealed, err2 := encoding.DecodeString(wrapped.Wrapped)
	if err1 != nil || err2 != nil {
		return nil, ErrInvalidFile
	}
	shared, err := private.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	recipient := private.PublicKey().Bytes()
	kek, err := deriveWrapKey(shared, ephemeralRaw, recipient)
	wipe(shared)
	if err != nil {
		return nil, err
	}
	defer wipe(kek)
	return crypto.Open(kek, nonce, sealed, recipient)
}

// Save encrypts the secrets under a new file key for every member.
func (f *File) Save() error {
	fileKey := make([]byte, 32)
	if _, err := rand.Read(fileKey); err != nil {
		return err
	}
	defer wipe(fileKey)
	format := fileFormat{Version: 1, Members: f.members}
	for _, member := range f.members {
		public, err := parsePublic(member.PublicKey)
		if err != nil {
			return err
		}
		wrapped, err := wrapFileKey(fileKey, public)
		if err != nil {
			return err
		}
		format.Keys = append(format.Keys, wrapped)
	}
	plain, err := json.Marshal(f.secrets)
	if err != nil {
		return err
	}
	defer wipe(plain)
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext, err := crypto.Seal(fileKey, nonce, plain, membersAAD(f.members))
	if err != nil {
		return err
	}
	format.Nonce, format.Ciphertext = encoding.EncodeToString(nonce), encoding.EncodeToString(ciphertext)
	raw, err := json.MarshalIndent(format, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(f.path, append(raw, '\n'))
}

func (f *File) Members() []Member { return append([]Member(nil), f.members...) }

func (f *File) AddMember(name, publicKey string) error {
	if !validName(name) || !ValidPublicKey(publicKey) {
		return ErrInvalidKey
	}
	for _, m := range f.members {
		if m.Name == name || m.PublicKey == publicKey {
			return ErrDuplicateMember
		}
	}
	f.members = append(f.members, Member{Name: name, PublicKey: publicKey})
	return nil
}

func (f *File) RemoveMember(name string) error {
	for i, m := range f.members {
		if m.Name == name {
			if len(f.members) == 1 {
				return ErrLastMember
			}
			f.members = append(f.members[:i], f.members[i+1:]...)
			return nil
		}
	}
	return ErrUnknownMember
}

func checkRef(ref domain.Reference) error {
	if !strings.HasPrefix(ref.String(), Prefix) {
		return ErrNotTeamRef
	}
	return nil
}

func (f *File) Set(ref domain.Reference, value []byte) error {
	if err := checkRef(ref); err != nil {
		return err
	}
	wipe(f.secrets[ref.String()])
	f.secrets[ref.String()] = append([]byte(nil), value...)
	return nil
}

func (f *File) Remove(ref domain.Reference) error {
	value, ok := f.secrets[ref.String()]
	if !ok {
		return ErrUnknownRef
	}
	wipe(value)
	delete(f.secrets, ref.String())
	return nil
}

func (f *File) Value(ref domain.Reference) ([]byte, bool) {
	value, ok := f.secrets[ref.String()]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), value...), true
}

func (f *File) References() []string {
	out := make([]string, 0, len(f.secrets))
	for ref := range f.secrets {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

func (f *File) Close() {
	for _, value := range f.secrets {
		wipe(value)
	}
	clear(f.secrets)
}

// IsTeamReference reports whether ref resolves from the team file.
func IsTeamReference(ref domain.Reference) bool { return strings.HasPrefix(ref.String(), Prefix) }

func validName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '@') {
			return false
		}
	}
	return true
}

func writeAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".envrune-team-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
