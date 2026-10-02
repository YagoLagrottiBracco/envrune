package cloud

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
)

// Store keeps the encoded State. app.Session implements it with the local
// vault, so the state is encrypted like every secret, and UpdateCloudState
// merges with writes from other processes.
type Store interface {
	CloudState() ([]byte, error)
	UpdateCloudState(change func([]byte) ([]byte, error)) error
}

// Service runs EnvRune Cloud operations for this device.
type Service struct {
	Store Store
	HTTP  *http.Client
}

var (
	ErrOtherAccount = errors.New("this vault is already set up for another EnvRune Cloud account or server; use another vault (ENVRUNE_VAULT) for it")
	ErrNotApproved  = errors.New("this device is waiting for approval; run `envrune cloud device approve` on a trusted device, or `envrune cloud recover`")
)

func (s *Service) state() (*State, error) {
	raw, err := s.Store.CloudState()
	if err != nil {
		return nil, err
	}
	defer wipe(raw)
	return parseState(raw)
}

// update applies change to the stored state, read again inside the vault
// write, so fields another process changed meanwhile are kept.
func (s *Service) update(change func(*State) error) error {
	return s.Store.UpdateCloudState(func(raw []byte) ([]byte, error) {
		st, err := parseState(raw)
		if err != nil {
			return nil, err
		}
		if err := change(st); err != nil {
			return nil, err
		}
		return json.Marshal(st)
	})
}

// signedIn returns the state and a client that persists refreshed tokens.
func (s *Service) signedIn() (*State, *Client, error) {
	st, err := s.state()
	if err != nil {
		return nil, nil, err
	}
	if st.Server == "" || st.Tokens.AccessToken == "" {
		return nil, nil, ErrSignedOut
	}
	c := &Client{Server: st.Server, HTTP: s.HTTP, Tokens: &st.Tokens, Refreshed: func(t Tokens) error {
		return s.update(func(st *State) error { st.Tokens = t; return nil })
	}}
	return st, c, nil
}

// ready is signedIn for commands that act with this device's keys.
func (s *Service) ready() (*State, *Client, *cloudcrypto.Device, error) {
	st, c, err := s.signedIn()
	if err != nil {
		return nil, nil, nil, err
	}
	if st.DeviceID == "" {
		return nil, nil, nil, ErrNoAccount
	}
	if !st.DeviceApproved {
		return nil, nil, nil, ErrNotApproved
	}
	device, err := st.device()
	if err != nil {
		return nil, nil, nil, err
	}
	return st, c, device, nil
}

// ---------------------------------------------------------------- signing in

// Login signs this vault in through the panel: it listens on 127.0.0.1,
// has the user open the authorize page, and waits for the panel to post the
// new session back. open shows or opens the address.
func (s *Service) Login(ctx context.Context, server string, open func(address string)) (*State, error) {
	server = strings.TrimRight(server, "/")
	if err := checkServer(server); err != nil {
		return nil, err
	}
	if err := (&Client{Server: server, HTTP: s.HTTP}).Health(ctx); err != nil {
		return nil, err
	}
	current, err := s.state()
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		listener.Close()
		return nil, err
	}
	state := base64.RawURLEncoding.EncodeToString(nonce)
	result := make(chan Tokens, 1)
	callback := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if r.ParseForm() != nil || subtle.ConstantTimeCompare([]byte(r.PostForm.Get("state")), []byte(state)) != 1 {
			http.Error(w, "This sign-in link is not the one the CLI is waiting for. Run envrune login again.", http.StatusBadRequest)
			return
		}
		expires, _ := strconv.ParseInt(r.PostForm.Get("expires_at"), 10, 64)
		t := Tokens{AccessToken: r.PostForm.Get("access_token"), RefreshToken: r.PostForm.Get("refresh_token"), ExpiresAt: expires}
		if t.AccessToken == "" || t.RefreshToken == "" {
			http.Error(w, "The session is missing. Run envrune login again.", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<!doctype html><title>EnvRune</title><p style=\"font-family:system-ui;margin:4rem auto;max-width:28rem\">%s</p>",
			html.EscapeString("The EnvRune CLI is signed in. You can close this tab."))
		select {
		case result <- t:
		default:
		}
	})}
	go func() { _ = callback.Serve(listener) }()
	defer callback.Close()

	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	open(server + "/cli/authorize?" + url.Values{"port": {port}, "state": {state}}.Encode())

	var tokens Tokens
	select {
	case tokens = <-result:
	case <-ctx.Done():
		return nil, fmt.Errorf("sign-in did not finish: %w", ctx.Err())
	}
	claims, err := parseClaims(tokens.AccessToken)
	if err != nil {
		return nil, err
	}
	if current.UserID != "" && current.DeviceID != "" && (current.UserID != claims.Subject || current.Server != server) {
		return nil, ErrOtherAccount
	}
	var out *State
	err = s.update(func(st *State) error {
		if st.UserID != "" && st.DeviceID != "" && (st.UserID != claims.Subject || st.Server != server) {
			return ErrOtherAccount
		}
		st.Server, st.UserID, st.Email, st.Tokens = server, claims.Subject, claims.Email, tokens
		out = st
		return nil
	})
	return out, err
}

// Logout forgets the session. The device keys stay, so signing in again
// needs no approval.
func (s *Service) Logout() error {
	return s.update(func(st *State) error { st.Tokens = Tokens{}; return nil })
}

// checkServer requires HTTPS, except on this computer for development.
func checkServer(server string) error {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return fmt.Errorf("the server address %q is not valid", server)
	}
	host := u.Hostname()
	local := host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return fmt.Errorf("the server address must use https: %s", server)
	}
	return nil
}

type claims struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
}

// parseClaims reads the user id from an access token. The server checks
// the token; the CLI only needs to know whose it is.
func parseClaims(token string) (*claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("the server sent a malformed session")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c claims
	if err != nil || json.Unmarshal(raw, &c) != nil || c.Subject == "" {
		return nil, errors.New("the server sent a malformed session")
	}
	return &c, nil
}

// ---------------------------------------------------------------- account and devices

// Status is what `envrune cloud whoami` shows. It reads only the vault.
type Status struct {
	Server, UserID, Email string
	SignedIn              bool
	DeviceID              string
	DeviceApproved        bool
	AccountFingerprint    string // empty until this device holds the account key
	DeviceFingerprint     string
}

func (s *Service) Status() (*Status, error) {
	st, err := s.state()
	if err != nil {
		return nil, err
	}
	out := &Status{Server: st.Server, UserID: st.UserID, Email: st.Email, SignedIn: st.Tokens.AccessToken != "",
		DeviceID: st.DeviceID, DeviceApproved: st.DeviceApproved}
	if account, err := st.account(); err == nil {
		out.AccountFingerprint = cloudcrypto.Fingerprint(account.Public)
	}
	if device, err := st.device(); err == nil {
		out.DeviceFingerprint = deviceFingerprint(device.Identity.Recipient().String(), device.SigningPublic())
	}
	return out, nil
}

// deviceFingerprint is what both screens show when a device is approved.
func deviceFingerprint(ageRecipient string, signingKey []byte) string {
	return cloudcrypto.Fingerprint([]byte(ageRecipient), signingKey)
}

// SetupResult tells the user what `envrune cloud init` did.
type SetupResult struct {
	Created            bool   // a new account; RecoveryKey is set
	RecoveryKey        []byte // show once, then wipe
	Pending            bool   // this device waits for approval
	Approved           bool   // a pending device was approved since the last run
	DeviceFingerprint  string
	AccountFingerprint string
}

// Setup creates the account on its first device, registers any other device
// as pending, and completes a pending device once another one approved it.
func (s *Service) Setup(ctx context.Context, deviceName string) (*SetupResult, error) {
	st, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	if st.DeviceApproved && len(st.AccountSeed) > 0 {
		account, err := st.account()
		if err != nil {
			return nil, err
		}
		return &SetupResult{AccountFingerprint: cloudcrypto.Fingerprint(account.Public)}, nil
	}
	remote, err := c.account(ctx)
	if err != nil {
		return nil, err
	}
	device, err := s.deviceKeys(st)
	if err != nil {
		return nil, err
	}
	fingerprint := deviceFingerprint(device.Identity.Recipient().String(), device.SigningPublic())

	if !remote.Registered {
		return s.createAccount(ctx, c, st.UserID, device, deviceName, remote)
	}
	registered := findDevice(remote.Devices, device.DeviceID)
	if registered == nil {
		pending := &cloudcrypto.RecipientCertificate{Kind: cloudcrypto.KindDevice, UserID: st.UserID, RecipientID: device.DeviceID,
			AgeRecipient: device.Identity.Recipient().String(), SigningKey: device.SigningPublic(), CreatedAt: time.Now()}
		if err := c.registerDevice(ctx, deviceName, pending); err != nil {
			return nil, err
		}
		return &SetupResult{Pending: true, DeviceFingerprint: fingerprint}, nil
	}
	approved, err := s.completeApproval(st.UserID, device, registered, remote.AccountKey)
	if err != nil || approved == nil {
		return &SetupResult{Pending: true, DeviceFingerprint: fingerprint}, err
	}
	return &SetupResult{Approved: true, DeviceFingerprint: fingerprint, AccountFingerprint: cloudcrypto.Fingerprint(approved.Public)}, nil
}

// deviceKeys returns this vault's device keys, creating and saving them the
// first time, before anything reaches the server.
func (s *Service) deviceKeys(st *State) (*cloudcrypto.Device, error) {
	if st.DeviceID != "" {
		return st.device()
	}
	id := make([]byte, 10)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	device, err := cloudcrypto.NewDevice(st.UserID, strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id)))
	if err != nil {
		return nil, err
	}
	err = s.update(func(st *State) error {
		if st.DeviceID != "" {
			return errors.New("another envrune process set up this device at the same time; run the command again")
		}
		st.DeviceID, st.DeviceIdentity, st.DeviceSigningSeed = device.DeviceID, device.Identity.String(), device.SigningSeed()
		return nil
	})
	return device, err
}

func (s *Service) createAccount(ctx context.Context, c *Client, userID string, device *cloudcrypto.Device, deviceName string, remote *accountJSON) (*SetupResult, error) {
	account, err := cloudcrypto.NewAccount(userID)
	if err != nil {
		return nil, err
	}
	recoveryKey, err := cloudcrypto.NewRecoveryKey()
	if err != nil {
		return nil, err
	}
	recoveryIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	backup, err := cloudcrypto.SealRecoveryBackup(recoveryKey, account, recoveryIdentity)
	if err != nil {
		return nil, err
	}
	// Keep the account key before registering it, so a failure afterwards
	// cannot leave an account whose key no device holds.
	if err := s.update(func(st *State) error { st.AccountSeed = account.Seed(); return nil }); err != nil {
		return nil, err
	}
	if err := c.registerAccount(ctx, account.Public, backup, account.CertifyRecovery(recoveryIdentity.Recipient().String())); err != nil {
		return nil, err
	}
	if err := s.certifyOwnDevice(ctx, c, account, device, deviceName, remote.Devices); err != nil {
		return nil, err
	}
	return &SetupResult{Created: true, RecoveryKey: recoveryKey[:], AccountFingerprint: cloudcrypto.Fingerprint(account.Public),
		DeviceFingerprint: deviceFingerprint(device.Identity.Recipient().String(), device.SigningPublic())}, nil
}

// certifyOwnDevice signs this device with the account key, registers or
// approves it on the server, and marks it approved here.
func (s *Service) certifyOwnDevice(ctx context.Context, c *Client, account *cloudcrypto.Account, device *cloudcrypto.Device, name string, remote []deviceJSON) error {
	cert := account.CertifyDevice(device.DeviceID, device.Identity.Recipient().String(), device.SigningPublic())
	var err error
	if existing := findDevice(remote, device.DeviceID); existing != nil && existing.Signature == nil {
		var wrapped []byte
		if wrapped, err = encryptTo(cert.AgeRecipient, account.Seed()); err == nil {
			err = c.approveDevice(ctx, cert, wrapped)
		}
	} else if existing == nil {
		err = c.registerDevice(ctx, name, cert)
	}
	if err != nil {
		return err
	}
	return s.update(func(st *State) error {
		st.AccountSeed, st.DeviceApproved = account.Seed(), true
		return nil
	})
}

// completeApproval takes the account key another device wrapped for this
// one, once it approved it. It returns nil while the device is pending.
func (s *Service) completeApproval(userID string, device *cloudcrypto.Device, registered *deviceJSON, accountKey ed25519.PublicKey) (*cloudcrypto.Account, error) {
	if registered.RevokedAt != nil {
		return nil, errors.New("this device was revoked; run `envrune cloud recover` to set it up again")
	}
	if registered.Signature == nil || len(registered.AccountKeyWrapped) == 0 {
		return nil, nil
	}
	seed, err := decryptWith(device.Identity, registered.AccountKeyWrapped)
	if err != nil {
		return nil, err
	}
	defer wipe(seed)
	account, err := cloudcrypto.AccountFromSeed(userID, seed)
	if err != nil {
		return nil, err
	}
	// The account key must be the registered one, and must have certified
	// exactly this device's keys.
	cert := registered.certificate()
	if !account.Public.Equal(accountKey) || cert.Verify(account.Public) != nil ||
		cert.AgeRecipient != device.Identity.Recipient().String() || !bytes.Equal(cert.SigningKey, device.SigningPublic()) {
		return nil, fmt.Errorf("the approval does not match this device's keys: %w", cloudcrypto.ErrUntrusted)
	}
	err = s.update(func(st *State) error {
		st.AccountSeed, st.DeviceApproved = account.Seed(), true
		return nil
	})
	return account, err
}

// Recover sets this device up with the recovery key: it opens the backup,
// certifies this device, and shares the keys wrapped for the recovery
// recipient with it. It returns how many environment keys it restored.
func (s *Service) Recover(ctx context.Context, key cloudcrypto.RecoveryKey, deviceName string) (int, error) {
	st, c, err := s.signedIn()
	if err != nil {
		return 0, err
	}
	remote, err := c.account(ctx)
	if err != nil {
		return 0, err
	}
	if !remote.Registered {
		return 0, errors.New("this account has no EnvRune Cloud keys yet; run `envrune cloud init`")
	}
	recovery, err := cloudcrypto.OpenRecoveryBackup(key, st.UserID, remote.RecoveryBackup)
	if err != nil {
		return 0, errors.New("the recovery key does not open this account's backup")
	}
	if !recovery.Account.Public.Equal(ed25519.PublicKey(remote.AccountKey)) {
		return 0, fmt.Errorf("the backup holds another account key than the registered one: %w", cloudcrypto.ErrUntrusted)
	}
	device, err := s.deviceKeys(st)
	if err != nil {
		return 0, err
	}
	if existing := findDevice(remote.Devices, device.DeviceID); existing != nil && existing.RevokedAt != nil {
		return 0, errors.New("this device was revoked; set it up with a new vault")
	}
	if err := s.certifyOwnDevice(ctx, c, recovery.Account, device, deviceName, remote.Devices); err != nil {
		return 0, err
	}
	st.DeviceApproved, st.AccountSeed = true, recovery.Account.Seed()
	target := recovery.Account.CertifyDevice(device.DeviceID, device.Identity.Recipient().String(), device.SigningPublic())
	return s.reshare(ctx, c, st, device, target, recovery.Identity)
}

// Device is one of the user's devices, for `envrune cloud device list`.
type Device struct {
	ID, Name, Kind string
	Pending        bool
	Revoked        bool
	This           bool
	Fingerprint    string
}

func (s *Service) Devices(ctx context.Context) ([]Device, error) {
	st, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	remote, err := c.account(ctx)
	if err != nil {
		return nil, err
	}
	var out []Device
	for _, d := range remote.Devices {
		if d.Kind != cloudcrypto.KindDevice {
			continue
		}
		out = append(out, Device{ID: d.ID, Name: d.Name, Kind: d.Kind, Pending: d.Signature == nil, Revoked: d.RevokedAt != nil,
			This: d.ID == st.DeviceID, Fingerprint: deviceFingerprint(d.AgeRecipient, d.SigningKey)})
	}
	return out, nil
}

// PendingDevice returns a device waiting for approval, to show its
// fingerprint before ApproveDevice.
func (s *Service) PendingDevice(ctx context.Context, id string) (*Device, error) {
	devices, err := s.Devices(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		if d.ID == id && d.Pending && !d.Revoked {
			return &d, nil
		}
	}
	return nil, fmt.Errorf("no device %s is waiting for approval", id)
}

// ApproveDevice certifies a pending device of this user, after the user
// compared its fingerprint on both screens, hands it the account key, and
// shares the environment keys this device holds with it.
func (s *Service) ApproveDevice(ctx context.Context, id, fingerprint string) (int, error) {
	st, c, device, err := s.ready()
	if err != nil {
		return 0, err
	}
	account, err := st.account()
	if err != nil {
		return 0, err
	}
	remote, err := c.account(ctx)
	if err != nil {
		return 0, err
	}
	pending := findDevice(remote.Devices, id)
	if pending == nil || pending.Signature != nil || pending.RevokedAt != nil || pending.Kind != cloudcrypto.KindDevice {
		return 0, fmt.Errorf("no device %s is waiting for approval", id)
	}
	// The server could swap the keys between listing and approving; the
	// fingerprint the user confirmed must still be the one signed.
	if deviceFingerprint(pending.AgeRecipient, pending.SigningKey) != fingerprint || len(pending.SigningKey) != ed25519.PublicKeySize {
		return 0, fmt.Errorf("device %s changed after you compared its fingerprint: %w", id, cloudcrypto.ErrUntrusted)
	}
	cert := account.CertifyDevice(id, pending.AgeRecipient, ed25519.PublicKey(pending.SigningKey))
	wrapped, err := encryptTo(cert.AgeRecipient, account.Seed())
	if err != nil {
		return 0, err
	}
	if err := c.approveDevice(ctx, cert, wrapped); err != nil {
		return 0, err
	}
	return s.reshare(ctx, c, st, device, cert, nil)
}

// RevokeDevice ends one of this user's devices, such as a lost one: the
// server stops serving it and deletes the keys wrapped for it. Then, since
// the device held those keys, it starts a new epoch in every environment
// that waits for one and that this user administers. The Handover lists
// those, and the ones left for someone who administers them. Whoever has
// the device may know the values it fetched: the server opens a guided
// rotation for them (docs/cloud-operations.md).
func (s *Service) RevokeDevice(ctx context.Context, id string) (*Handover, error) {
	st, c, err := s.signedIn()
	if err != nil {
		return nil, err
	}
	if id == st.DeviceID {
		return nil, errors.New("this is the device you are using; revoke it from another one")
	}
	if err := c.revokeDevice(ctx, id); err != nil {
		return nil, err
	}
	h := &Handover{}
	if st.DeviceID == "" || !st.DeviceApproved {
		return h, nil
	}
	orgs, err := c.orgs(ctx)
	if err != nil {
		return h, err
	}
	for _, o := range orgs {
		v, err := s.view(ctx, c, o.Slug)
		if err != nil {
			return h, err
		}
		me, err := v.trust.Verify(v.certs, st.UserID)
		if err != nil {
			continue
		}
		for _, p := range v.snap.Projects {
			for _, e := range p.Environments {
				if !e.NeedsRotation {
					continue
				}
				name := o.Slug + "/" + p.Slug + "/" + e.Slug
				if !me.CanAdminister(p.Slug, e.Slug) {
					h.Left = append(h.Left, name)
					continue
				}
				if _, err := s.Rotate(ctx, o.Slug, p.Slug, e.Slug, false); err != nil {
					return h, fmt.Errorf("%s: %w", name, err)
				}
				h.Rotated = append(h.Rotated, name)
			}
		}
	}
	return h, nil
}

// reshare wraps every environment key this user holds for target, another
// of their own devices. recovery, when set, also unwraps the copies made for
// the recovery recipient.
func (s *Service) reshare(ctx context.Context, c *Client, st *State, device *cloudcrypto.Device, target *cloudcrypto.RecipientCertificate, recovery *age.X25519Identity) (int, error) {
	orgs, err := c.orgs(ctx)
	if err != nil {
		return 0, err
	}
	identities := map[string]age.Identity{device.DeviceID: device.Identity}
	if recovery != nil {
		identities[cloudcrypto.KindRecovery] = recovery
	}
	shared := 0
	for _, o := range orgs {
		v, err := s.view(ctx, c, o.Slug)
		if err != nil {
			return shared, err
		}
		me, err := v.trust.Verify(v.certs, st.UserID)
		if err != nil {
			continue
		}
		for _, p := range v.snap.Projects {
			for _, e := range p.Environments {
				if !me.CanUse(p.Slug, e.Slug) {
					continue
				}
				payload, err := c.fetchEnvironment(ctx, e.ID, device.DeviceID)
				if err != nil {
					return shared, err
				}
				key, err := v.verifier(&p, &e, payload).key(payload, identities, st.UserID)
				if errors.Is(err, ErrNoKey) {
					continue
				}
				if err != nil {
					return shared, fmt.Errorf("%s/%s/%s: %w", o.Slug, p.Slug, e.Slug, err)
				}
				wrapped, err := device.Wrap(key, target)
				key.Wipe()
				if err != nil {
					return shared, err
				}
				if err := c.putWrappedKeys(ctx, e.ID, payload.Epoch, device.DeviceID, []map[string]any{wrappedToJSON(wrapped, false)}); err != nil {
					return shared, err
				}
				shared++
			}
		}
	}
	return shared, nil
}

func findDevice(devices []deviceJSON, id string) *deviceJSON {
	for i := range devices {
		if devices[i].ID == id && devices[i].Kind == cloudcrypto.KindDevice {
			return &devices[i]
		}
	}
	return nil
}

func encryptTo(recipient string, plain []byte) ([]byte, error) {
	r, err := age.ParseX25519Recipient(recipient)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decryptWith(identity age.Identity, sealed []byte) ([]byte, error) {
	r, err := age.Decrypt(bytes.NewReader(sealed), identity)
	if err != nil {
		return nil, cloudcrypto.ErrDecrypt
	}
	out, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		wipe(out)
		return nil, cloudcrypto.ErrDecrypt
	}
	return out, nil
}
