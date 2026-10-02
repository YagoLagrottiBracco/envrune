package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/clipboard"
	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
	"github.com/YagoLagrottiBracco/envrune/internal/cloudcrypto"
	"github.com/YagoLagrottiBracco/envrune/internal/generator"
	"github.com/YagoLagrottiBracco/envrune/internal/vault"
)

const cloudUsage = `cloud <command>
  whoami                                   Show the account, this device, and their fingerprints
  init [--name device]                     Create your account, or register this device
  recover [--name device]                  Set up this device with your recovery key
  device list | approve <id> | revoke <id>
  org list | show <org>
  org create <org> [--name n] [--roots email[,email]]   Up to two more root holders
  org join <org> --fingerprint f           Trust an organization you were added to
  org set <org> --offline-days n|off       How long devices work without syncing
  member add <org> <email> --role r --scope s[,s]
  member set <org> <user-id> --role r --scope s[,s]
  member remove <org> <user-id>
  project create <org> <project> [--name n]
  env create <org/project/env>
  set <org/project/env/name>               Store a value (asked twice, never echoed)
  set <org/project/env/name> --generate [--length n]
  set ... --transition 24h                 Say how long the previous value still works
  set ... --sensitive --allow-host h[,h]   A value members use but never receive
  set ... --sensitive --allow-host h --client-cert c.pem --client-key k.pem
  status <org/project/env>                 Who already has the current values
  copy <org/project/env/name> [--clear-after 30s]
  pull <org/project/env> [--allow-older]   Refresh this device's copy of an environment
  sync                                     Pull every environment you can use
  share <org>                              Wrap your keys for new members, devices, and tokens
  rotate <org/project/env> [--accept-removed]  Start a new key epoch
  rotation <org> [--all]                   List the values someone who left could read
  rotation accept <org/project/env/name>   Record that a value stays as it is
  token create <org> --scope s[,s] [--name n] [--expires 90d]
  token revoke <id>
  import-team <org/project/env> [--relink] Move envrune.team.json's values to the cloud
  proxy keygen                             A proxy identity, for whoever runs a server
  audit export <org> [--output file]       Download the audit log and verify it
  audit verify <file> [--since older-file] Check an export again, offline`

// cloudTimeout bounds one command's requests; login waits for the browser
// separately.
const cloudTimeout = 2 * time.Minute

func (w Workspace) cloudService() *cloud.Service { return &cloud.Service{Store: w.Session} }

// cloudFail shows what went wrong. Errors from internal/cloud name
// organizations, environments, and secrets, never a value.
func (w Workspace) cloudFail(err error) int {
	message := describe(err, "")
	if message == "" {
		message = sentence(strings.TrimRight(err.Error(), "."))
	}
	w.status().Error(message)
	return 1
}

func cloudContext() (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	ctx, cancel := context.WithTimeout(ctx, cloudTimeout)
	return ctx, func() { cancel(); stop() }
}

func (w Workspace) confirmChoice(question string) bool {
	if w.ReadChoice == nil {
		return false
	}
	answer, err := w.ReadChoice(question + " [y/N]")
	return err == nil && (strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes"))
}

func (w Workspace) login(argv []string) int {
	a, err := parseArgs(argv, []string{"server"}, nil, false)
	if err != nil || len(a.positional) != 0 {
		return w.usageError("login [--server <url>]")
	}
	server := a.options["server"]
	if server == "" {
		server = os.Getenv("ENVRUNE_CLOUD_SERVER")
	}
	if server == "" {
		server = cloud.DefaultServer
	}
	if server == "" {
		w.status().Error("Pass the EnvRune Cloud address with --server or ENVRUNE_CLOUD_SERVER.")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	st, err := w.cloudService().Login(ctx, server, func(address string) {
		w.status().Info("Opening your browser to sign in. If it does not open, visit:")
		fmt.Fprintf(w.Stderr, "\n    %s\n\n", address)
		openBrowser(address)
	})
	if err != nil {
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("Signed in to %s as %s.", st.Server, st.Email))
	if st.DeviceID == "" {
		w.status().Info("Next, run `envrune cloud init` to set up your keys on this device.")
	}
	return 0
}

func (w Workspace) logout(argv []string) int {
	if len(argv) != 0 {
		return w.usageError("logout")
	}
	if err := w.cloudService().Logout(); err != nil {
		return w.cloudFail(err)
	}
	w.status().Success("Signed out. This device's keys stay in the vault, so signing in again needs no approval.")
	return 0
}

func (w Workspace) cloud(argv []string) int {
	if len(argv) == 0 {
		return w.usageError(cloudUsage)
	}
	sub, rest := argv[0], argv[1:]
	switch sub {
	case "whoami":
		return w.cloudWhoami(rest)
	case "init":
		return w.cloudInit(rest)
	case "recover":
		return w.cloudRecover(rest)
	case "device":
		return w.cloudDevice(rest)
	case "org":
		return w.cloudOrg(rest)
	case "member":
		return w.cloudMember(rest)
	case "project":
		return w.cloudProject(rest)
	case "env":
		return w.cloudEnv(rest)
	case "set":
		return w.cloudSet(rest)
	case "copy":
		return w.cloudCopy(rest)
	case "pull":
		return w.cloudPull(rest)
	case "sync":
		return w.cloudSync(rest)
	case "share":
		return w.cloudShare(rest)
	case "rotate":
		return w.cloudRotate(rest)
	case "status":
		return w.cloudStatus(rest)
	case "rotation":
		return w.cloudRotation(rest)
	case "token":
		return w.cloudToken(rest)
	case "audit":
		return w.cloudAudit(rest)
	case "import-team":
		return w.cloudImportTeam(rest)
	case "proxy":
		return w.cloudProxy(rest)
	}
	return w.usageError(cloudUsage)
}

func (w Workspace) cloudWhoami(argv []string) int {
	if len(argv) != 0 {
		return w.usageError("cloud whoami")
	}
	st, err := w.cloudService().Status()
	if err != nil {
		return w.cloudFail(err)
	}
	if st.UserID == "" {
		w.status().Warn("Not signed in. Run `envrune login`.")
		return 1
	}
	out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(out, "server\t%s\n", st.Server)
	fmt.Fprintf(out, "account\t%s (%s)\n", st.Email, st.UserID)
	if st.AccountFingerprint != "" {
		fmt.Fprintf(out, "account fingerprint\t%s\n", st.AccountFingerprint)
	}
	if st.DeviceID != "" {
		state := "approved"
		if !st.DeviceApproved {
			state = "waiting for approval"
		}
		fmt.Fprintf(out, "device\t%s (%s)\n", st.DeviceID, state)
		fmt.Fprintf(out, "device fingerprint\t%s\n", st.DeviceFingerprint)
	}
	out.Flush()
	if !st.SignedIn {
		w.status().Warn("Signed out. Run `envrune login` to sync.")
	}
	return 0
}

func deviceName(a args) string {
	if name := a.options["name"]; name != "" {
		return name
	}
	host, _ := os.Hostname()
	return host
}

func (w Workspace) cloudInit(argv []string) int {
	a, err := parseArgs(argv, []string{"name"}, nil, false)
	if err != nil || len(a.positional) != 0 {
		return w.usageError("cloud init [--name <device>]")
	}
	ctx, cancel := cloudContext()
	defer cancel()
	result, err := w.cloudService().Setup(ctx, deviceName(a))
	if err != nil {
		return w.cloudFail(err)
	}
	switch {
	case result.Created:
		defer wipe(result.RecoveryKey)
		w.status().Success("Created your EnvRune Cloud account on this device.")
		w.status().Warn("Write down this recovery key and keep it offline. It is shown only once.")
		fmt.Fprintf(w.Stdout, "\n    %s\n\n", vault.FormatRecoveryKey(result.RecoveryKey))
		w.status().Info("If you lose every device, `envrune cloud recover` with this key restores your access.")
		w.status().Info("Account fingerprint: " + result.AccountFingerprint + ". An admin compares it before adding you.")
	case result.Pending:
		w.status().Warn("This device is waiting for approval. On a device you already use, run:")
		fmt.Fprintf(w.Stderr, "\n    envrune cloud device approve %s\n\n", w.deviceID())
		w.status().Info("Check that it shows this fingerprint: " + result.DeviceFingerprint)
		w.status().Info("Then run `envrune cloud init` here again. Lost your other devices? Run `envrune cloud recover`.")
	case result.Approved:
		w.status().Success("This device was approved. Run `envrune cloud sync` to fetch your environments.")
	default:
		w.status().Success("This device is already set up. Account fingerprint: " + result.AccountFingerprint)
	}
	return 0
}

func (w Workspace) deviceID() string {
	st, err := w.cloudService().Status()
	if err != nil {
		return "<id>"
	}
	return st.DeviceID
}

func (w Workspace) cloudRecover(argv []string) int {
	a, err := parseArgs(argv, []string{"name"}, nil, false)
	if err != nil || len(a.positional) != 0 {
		return w.usageError("cloud recover [--name <device>]")
	}
	text, err := w.ReadSecret("Recovery key")
	if err != nil {
		return w.fail(err, "Secure interactive input is required.")
	}
	raw, err := vault.ParseRecoveryKey(string(text))
	wipe(text)
	if err != nil {
		return w.fail(err, "The recovery key is invalid.")
	}
	key := cloudcrypto.RecoveryKey(raw)
	wipe(raw)
	defer wipe(key[:])
	ctx, cancel := cloudContext()
	defer cancel()
	restored, err := w.cloudService().Recover(ctx, key, deviceName(a))
	if err != nil {
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("This device is set up again, with %d %s restored.", restored, plural(restored, "environment key", "environment keys")))
	w.status().Info("Revoke devices you lost with `envrune cloud device revoke <id>`.")
	return 0
}

func (w Workspace) cloudDevice(argv []string) int {
	const usage = "cloud device list | approve <id> | revoke <id>"
	ctx, cancel := cloudContext()
	defer cancel()
	s := w.cloudService()
	switch {
	case len(argv) == 1 && argv[0] == "list":
		devices, err := s.Devices(ctx)
		if err != nil {
			return w.cloudFail(err)
		}
		out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(out, "ID\tNAME\tSTATE\tFINGERPRINT")
		for _, d := range devices {
			state := "approved"
			switch {
			case d.Revoked:
				state = "revoked"
			case d.Pending:
				state = "pending"
			}
			if d.This {
				state += " (this device)"
			}
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", d.ID, d.Name, state, d.Fingerprint)
		}
		out.Flush()
		return 0
	case len(argv) == 2 && argv[0] == "approve":
		device, err := s.PendingDevice(ctx, argv[1])
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Info(fmt.Sprintf("Device %s (%s) shows this fingerprint:", device.ID, device.Name))
		fmt.Fprintf(w.Stderr, "\n    %s\n\n", device.Fingerprint)
		if !w.confirmChoice("Does the new device show exactly the same fingerprint?") {
			w.status().Error("Not approved. If the fingerprints differ, someone else may have registered that device.")
			return 1
		}
		shared, err := s.ApproveDevice(ctx, device.ID, device.Fingerprint)
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("Approved %s and shared %d %s with it. Run `envrune cloud init` on it to finish.",
			device.ID, shared, plural(shared, "environment key", "environment keys")))
		return 0
	case len(argv) == 2 && argv[0] == "revoke":
		h, err := s.RevokeDevice(ctx, argv[1])
		if h != nil && len(h.Rotated) > 0 {
			w.status().Info("Started a new key for " + strings.Join(h.Rotated, ", ") + ", which that device held.")
		}
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Success("Revoked " + argv[1] + ". The server no longer serves it.")
		for _, env := range h.Left {
			w.status().Warn(fmt.Sprintf("It held a key of %s, which you do not administer: someone who does must run `envrune cloud rotate %s`.", env, env))
		}
		w.status().Warn("Whoever has that device may know the values it fetched. `envrune cloud rotation <org>` lists each one to replace.")
		return 0
	}
	return w.usageError(usage)
}

func (w Workspace) cloudOrg(argv []string) int {
	const usage = "cloud org list | create <org> [--name <name>] [--roots <email[,email]>] | show <org> | join <org> --fingerprint <fingerprint> | set <org> --offline-days <n|off>"
	a, err := parseArgs(argv, []string{"name", "roots", "fingerprint", "offline-days"}, nil, false)
	if err != nil || len(a.positional) == 0 {
		return w.usageError(usage)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	s := w.cloudService()
	switch {
	case len(a.positional) == 1 && a.positional[0] == "list":
		orgs, err := s.Orgs(ctx)
		if err != nil {
			return w.cloudFail(err)
		}
		out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(out, "ORG\tNAME\tROLE")
		for _, o := range orgs {
			fmt.Fprintf(out, "%s\t%s\t%s\n", o.Slug, o.Name, o.Role)
		}
		out.Flush()
		return 0
	case len(a.positional) == 2 && a.positional[0] == "create":
		name := a.options["name"]
		if name == "" {
			name = a.positional[1]
		}
		emails := splitScope(a.options["roots"])
		if len(emails) > cloud.MaxExtraRoots {
			w.status().Error(fmt.Sprintf("An organization has at most %d more root holders.", cloud.MaxExtraRoots))
			return 2
		}
		// A root holder can sign anyone into the organization, forever: the
		// founder confirms each key like a new member's, before it exists.
		var roots []*cloud.Account
		for _, email := range emails {
			account, err := s.LookupAccount(ctx, email)
			if err != nil {
				return w.cloudFail(err)
			}
			w.status().Info(fmt.Sprintf("The server says %s has this account fingerprint:", email))
			fmt.Fprintf(w.Stderr, "\n    %s\n\n", account.Fingerprint)
			if !w.confirmChoice(fmt.Sprintf("Did %s confirm the same fingerprint (`envrune cloud whoami`) over another channel?", email)) {
				w.status().Error("Not created. A root holder can add anyone to the organization, and can never be removed: compare the fingerprint first.")
				return 1
			}
			roots = append(roots, account)
		}
		org, err := s.CreateOrg(ctx, a.positional[1], name, roots...)
		if err != nil {
			return w.cloudFail(err)
		}
		if len(roots) == 0 {
			w.status().Success(fmt.Sprintf("Created %s. Your account key is its root.", org.Slug))
			w.status().Info("If you lose every device and your recovery key, nobody can add owners or admins to it again. `--roots` names up to two more root holders, only when creating it.")
		} else {
			w.status().Success(fmt.Sprintf("Created %s. Its root is your account key and %s; this cannot change.", org.Slug, strings.Join(emails, " and ")))
		}
		w.status().Info("Organization fingerprint, which members check when they join: " + org.Fingerprint)
		return 0
	case len(a.positional) == 2 && a.positional[0] == "join":
		if a.options["fingerprint"] == "" {
			return w.usageError(usage)
		}
		org, err := s.JoinOrg(ctx, a.positional[1], a.options["fingerprint"])
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("%s is the organization you were told about. You are %s. Run `envrune cloud sync` to fetch its environments.", org.Slug, org.Role))
		return 0
	case len(a.positional) == 2 && a.positional[0] == "set":
		days := 0
		if raw := a.options["offline-days"]; raw != "off" {
			if days, err = strconv.Atoi(raw); err != nil || days < 1 {
				return w.usageError(usage)
			}
		}
		if err := s.SetOfflineDays(ctx, a.positional[1], days); err != nil {
			return w.cloudFail(err)
		}
		if days == 0 {
			w.status().Success(fmt.Sprintf("Devices may use their copies of %s's environments without syncing for as long as they like.", a.positional[1]))
			return 0
		}
		w.status().Success(fmt.Sprintf("Devices now refuse a copy of %s's environments that was not synced for %d %s. Each learns this the next time it syncs.",
			a.positional[1], days, plural(days, "day", "days")))
		w.status().Info("This stops a laptop that no longer syncs, such as a removed member's. It does not take back a value they already saw.")
		return 0
	case len(a.positional) == 2 && a.positional[0] == "show":
		org, err := s.ShowOrg(ctx, a.positional[1])
		if err != nil {
			return w.cloudFail(err)
		}
		w.printOrg(org)
		return 0
	}
	return w.usageError(usage)
}

func (w Workspace) printOrg(org *cloud.Org) {
	if org.FirstSeen {
		w.status().Warn("This device trusted the organization's root as the server showed it. Compare the fingerprint below with a member over another channel.")
	}
	out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(out, "%s\t%s\n", org.Slug, org.Name)
	fmt.Fprintf(out, "fingerprint\t%s\n", org.Fingerprint)
	if org.OfflineDays > 0 {
		fmt.Fprintf(out, "offline\t%d %s without syncing\n", org.OfflineDays, plural(org.OfflineDays, "day", "days"))
	}
	for _, r := range org.Roots {
		fmt.Fprintf(out, "root\t%s\t%s\n", r.UserID, r.Fingerprint)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "MEMBER\tROLE\tSCOPE\tFINGERPRINT")
	for _, m := range org.Members {
		fingerprint := m.Fingerprint
		if !m.Verified {
			fingerprint = "UNVERIFIED: no certificate chain to the root"
		}
		fmt.Fprintf(out, "%s\t%s\t%s\t%s\n", m.UserID, m.Role, strings.Join(m.Scope, ","), fingerprint)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "ENVIRONMENT\tEPOCH\tSECRETS")
	for _, p := range org.Projects {
		for _, e := range p.Environments {
			note := ""
			if e.NeedsRotation {
				note = " (needs rotation)"
			}
			fmt.Fprintf(out, "%s/%s\t%d%s\t%d\n", p.Slug, e.Slug, e.Epoch, note, len(e.Secrets)+len(e.Sensitive))
		}
	}
	listed := false
	for _, p := range org.Projects {
		for _, e := range p.Environments {
			for _, sec := range e.Sensitive {
				if !listed {
					fmt.Fprintln(out)
					fmt.Fprintln(out, "SENSITIVE SECRET\tVERSION\tSENT ONLY TO")
					listed = true
				}
				where := strings.Join(sec.Hosts, ", ")
				if !sec.Verified {
					where += "  UNVERIFIED: not signed by an owner or admin for the identity this device trusts"
				}
				fmt.Fprintf(out, "%s/%s/%s\t%d\t%s\n", p.Slug, e.Slug, sec.Name, sec.Version, where)
			}
		}
	}
	out.Flush()
}

func splitScope(raw string) []string {
	var scope []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			scope = append(scope, s)
		}
	}
	return scope
}

func (w Workspace) cloudMember(argv []string) int {
	const usage = "cloud member add <org> <email> --role <role> --scope <s[,s]> | set <org> <user-id> --role <role> --scope <s[,s]> | remove <org> <user-id>"
	a, err := parseArgs(argv, []string{"role", "scope"}, nil, false)
	if err != nil || len(a.positional) != 3 {
		return w.usageError(usage)
	}
	action, org, who := a.positional[0], a.positional[1], a.positional[2]
	role, scope := a.options["role"], splitScope(a.options["scope"])
	if role == cloudcrypto.RoleOwner && len(scope) == 0 {
		scope = []string{"*"}
	}
	ctx, cancel := cloudContext()
	defer cancel()
	s := w.cloudService()
	switch action {
	case "add", "set":
		if role == "" || len(scope) == 0 {
			return w.usageError(usage)
		}
		var h *cloud.Handover
		if action == "add" {
			account, err := s.LookupAccount(ctx, who)
			if err != nil {
				return w.cloudFail(err)
			}
			w.status().Info(fmt.Sprintf("The server says %s has this account fingerprint:", who))
			fmt.Fprintf(w.Stderr, "\n    %s\n\n", account.Fingerprint)
			if !w.confirmChoice(fmt.Sprintf("Did %s confirm the same fingerprint (`envrune cloud whoami`) over another channel?", who)) {
				w.status().Error("Not added. Compare the fingerprint first: a different one means the key is not theirs.")
				return 1
			}
			h, err = s.AddMember(ctx, org, account, role, scope)
		} else {
			h, err = s.ChangeMember(ctx, org, who, role, scope)
		}
		if err != nil {
			w.handover(org, who, h)
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("%s is %s of %s (%s). Shared %d %s.", who, role, org, strings.Join(scope, ", "),
			h.Shared, plural(h.Shared, "environment", "environments")))
		w.handover(org, who, h)
		if action == "add" {
			w.status().Info("Send them this over a channel the server does not control, such as the call where you compared fingerprints:")
			fmt.Fprintf(w.Stdout, "\n    envrune cloud org join %s --fingerprint %s\n\n", org, h.OrgFingerprint)
		}
		return 0
	case "remove":
		h, err := s.RemoveMember(ctx, org, who)
		if err != nil {
			w.handover(org, who, h)
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("Removed %s.", who))
		w.handover(org, who, h)
		w.status().Warn(fmt.Sprintf("They may still know the values they could read. `envrune cloud rotation %s` lists each one to replace.", org))
		return 0
	}
	return w.usageError(usage)
}

// handover reports what a membership change did, or got done before it
// failed, besides signing the change.
func (w Workspace) handover(org, who string, h *cloud.Handover) {
	if h == nil {
		return
	}
	if len(h.Rotated) > 0 {
		w.status().Info(fmt.Sprintf("Started a new key for %s, and signed again what %s had signed there.", strings.Join(h.Rotated, ", "), who))
	}
	if len(h.Reissued) > 0 {
		w.status().Info(fmt.Sprintf("Signed again the %s %s had signed: %s.", plural(len(h.Reissued), "membership", "memberships"), who, strings.Join(h.Reissued, ", ")))
	}
	if len(h.Revoked) > 0 {
		w.status().Info(fmt.Sprintf("Revoked the machine %s they created: %s. Create new ones for CI.", plural(len(h.Revoked), "token", "tokens"), strings.Join(h.Revoked, ", ")))
	}
	for _, env := range h.Left {
		w.status().Warn(fmt.Sprintf("You do not administer %s, where %s could write or read. Until someone who does runs `envrune cloud rotate %s/%s --accept-removed`, its values may not verify.", env, who, org, env))
	}
	if len(h.Orphaned) > 0 {
		w.status().Warn(fmt.Sprintf("%s had signed %s, which you may not sign: an owner must add them again with `envrune cloud member set`.", who, strings.Join(h.Orphaned, ", ")))
	}
}

func (w Workspace) cloudProject(argv []string) int {
	a, err := parseArgs(argv, []string{"name"}, nil, false)
	if err != nil || len(a.positional) != 3 || a.positional[0] != "create" {
		return w.usageError("cloud project create <org> <project> [--name <name>]")
	}
	name := a.options["name"]
	if name == "" {
		name = a.positional[2]
	}
	ctx, cancel := cloudContext()
	defer cancel()
	if err := w.cloudService().CreateProject(ctx, a.positional[1], a.positional[2], name); err != nil {
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("Created %s/%s. Add environments with `envrune cloud env create %s/%s/<env>`.",
		a.positional[1], a.positional[2], a.positional[1], a.positional[2]))
	return 0
}

func (w Workspace) cloudEnv(argv []string) int {
	if len(argv) != 2 || argv[0] != "create" {
		return w.usageError("cloud env create <org/project/env>")
	}
	path, err := cloud.ParsePath(argv[1], false)
	if err != nil {
		return w.cloudFail(err)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	if err := w.cloudService().CreateEnvironment(ctx, path.Org, path.Project, path.Env); err != nil {
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("Created %s with its first key, shared with everyone who may use it.", path))
	return 0
}

func (w Workspace) cloudSet(argv []string) int {
	const usage = "cloud set <org/project/env/name> [--generate [--length <n>]] [--transition <24h|7d>] [--sensitive --allow-host <host[,host]> [--client-cert <file> --client-key <file>]]"
	a, err := parseArgs(argv, []string{"length", "transition", "allow-host", "client-cert", "client-key"}, []string{"generate", "sensitive"}, false)
	certFile, keyFile := a.options["client-cert"], a.options["client-key"]
	if (certFile == "") != (keyFile == "") || (certFile != "" && (!a.flags["sensitive"] || a.flags["generate"])) {
		return w.usageError(usage)
	}
	_, hasLength := a.options["length"]
	hosts := splitScope(a.options["allow-host"])
	_, hasTransition := a.options["transition"]
	if err != nil || len(a.positional) != 1 || (hasLength && !a.flags["generate"]) ||
		a.flags["sensitive"] != (len(hosts) > 0) || (a.flags["sensitive"] && hasTransition) {
		return w.usageError(usage)
	}
	var transition time.Duration
	if raw, ok := a.options["transition"]; ok {
		if transition, err = parseDays(raw, 0); err != nil || transition <= 0 {
			return w.usageError(usage)
		}
	}
	path, err := cloud.ParsePath(a.positional[0], true)
	if err != nil {
		return w.cloudFail(err)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	// A sensitive value is sealed to the server, which is the one exception
	// to the server never reading a value: the person agrees to it, having
	// seen which key it is sealed to, before typing the value.
	var proxy *cloud.ProxyIdentity
	if a.flags["sensitive"] {
		if proxy, err = w.cloudService().Proxy(ctx); err != nil {
			return w.cloudFail(err)
		}
		w.status().Warn(fmt.Sprintf("A sensitive secret is sealed to the server, which sends it only to %s. Members use it without receiving it; the server, and whoever runs it, can read it.", strings.Join(hosts, ", ")))
		if !proxy.Pinned {
			w.status().Info("This server's proxy identity has this fingerprint. Whoever runs the server can confirm it:")
			fmt.Fprintf(w.Stderr, "\n    %s\n\n", proxy.Fingerprint)
			if !w.confirmChoice("Seal sensitive values to this identity from now on?") {
				w.status().Error("Nothing was stored.")
				return 1
			}
		}
	}
	if certFile != "" {
		// A client certificate and its key, for a service that identifies
		// callers that way: sealed like a value, presented by the server.
		certificate, err := readSecretFile(certFile)
		if err != nil {
			w.status().Error(err.Error())
			return 1
		}
		key, err := readSecretFile(keyFile)
		if err != nil {
			w.status().Error(err.Error())
			return 1
		}
		defer wipe(key)
		version, err := w.cloudService().SetSensitiveCertificate(ctx, path, certificate, key, hosts, proxy.Fingerprint)
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("Stored %s, version %d: a client certificate the server presents to %s.", path, version, strings.Join(hosts, ", ")))
		w.status().Info("Nobody can read it back, you included. Keep the files somewhere safe or delete them.")
		return 0
	}
	var value []byte
	if a.flags["generate"] {
		length := 32
		if hasLength {
			if length, err = strconv.Atoi(a.options["length"]); err != nil {
				return w.usageError(usage)
			}
		}
		if value, err = generator.New(length); err != nil {
			return w.fail(err, "The value could not be generated.")
		}
	} else if value, err = readConfirmedValue(w.ReadSecret, "Secret value"); err != nil {
		return w.fail(err, "Secure interactive input is required.")
	}
	defer wipe(value)
	if a.flags["sensitive"] {
		version, err := w.cloudService().SetSensitive(ctx, path, value, hosts, proxy.Fingerprint)
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("Stored %s, version %d, as a sensitive secret for %s.", path, version, strings.Join(hosts, ", ")))
		w.status().Info("Nobody can read it back, you included. To replace it, set it again.")
		return 0
	}
	version, err := w.cloudService().Set(ctx, path, value)
	if err != nil {
		return w.cloudFail(err)
	}
	env := path
	env.Name = ""
	defer func() {
		w.status().Info(fmt.Sprintf("Devices pick it up the next time they run a command. `envrune cloud status %s` shows who has.", env))
	}()
	if transition > 0 {
		until := time.Now().Add(transition)
		if err := w.cloudService().SetTransition(ctx, path, until); err != nil {
			w.status().Warn("The value was stored, but the transition was not recorded: " + err.Error())
		} else {
			defer w.status().Info("The previous value is expected to work until " + until.Local().Format("2006-01-02 15:04") + ".")
		}
	}
	if a.flags["generate"] {
		w.status().Success(fmt.Sprintf("Stored a new %d-character value as %s, version %d.", len(value), path, version))
		w.status().Info("Restart what uses it. If a provider issues this value, such as an API key, replace it there and store it with `cloud set` instead.")
		return 0
	}
	w.status().Success(fmt.Sprintf("Stored %s, version %d.", path, version))
	return 0
}

func (w Workspace) cloudCopy(argv []string) int {
	const usage = "cloud copy <org/project/env/name> [--clear-after 30s]"
	a, err := parseArgs(argv, []string{"clear-after"}, nil, false)
	if err != nil || len(a.positional) != 1 {
		return w.usageError(usage)
	}
	delay := 30 * time.Second
	if raw, ok := a.options["clear-after"]; ok {
		if delay, err = time.ParseDuration(raw); err != nil || delay <= 0 {
			return w.usageError(usage)
		}
	}
	path, err := cloud.ParsePath(a.positional[0], true)
	if err != nil {
		return w.cloudFail(err)
	}
	env := path
	env.Name = ""
	values, role, err := w.cloudService().Values(env)
	if err != nil {
		return w.cloudFail(err)
	}
	defer func() {
		for _, v := range values {
			wipe(v)
		}
	}()
	// Consumers hold the key so their programs can run; the CLI keeps values
	// off their screen and clipboard (docs/cloud-crypto.md, Roles).
	if role == cloudcrypto.RoleConsumer {
		w.status().Error("Your role (consumer) lets programs use values, not copy them.")
		return 1
	}
	value, ok := values[path.Name]
	if !ok {
		w.status().Error(fmt.Sprintf("%s has no secret %s. Run `envrune cloud pull %s` if it is new.", env, path.Name, env))
		return 1
	}
	if err := clipboard.Copy(value, delay); err != nil {
		return w.fail(err, "The clipboard is unavailable.")
	}
	w.status().Success(fmt.Sprintf("Copied %s to the clipboard. It will be cleared in %s.", path, delay))
	return 0
}

func (w Workspace) cloudPull(argv []string) int {
	a, err := parseArgs(argv, nil, []string{"allow-older"}, false)
	if err != nil || len(a.positional) != 1 {
		return w.usageError("cloud pull <org/project/env> [--allow-older]")
	}
	path, err := cloud.ParsePath(a.positional[0], false)
	if err != nil {
		return w.cloudFail(err)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	secrets, err := w.cloudService().Pull(ctx, path, a.flags["allow-older"])
	if err != nil {
		return w.cloudFail(err)
	}
	out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
	for _, s := range secrets {
		fmt.Fprintf(out, "%s\tv%d\n", s.Name, s.Version)
	}
	out.Flush()
	w.status().Success(fmt.Sprintf("Pulled %s: %d %s, verified.", path, len(secrets), plural(len(secrets), "secret", "secrets")))
	return 0
}

func (w Workspace) cloudSync(argv []string) int {
	if len(argv) != 0 {
		return w.usageError("cloud sync")
	}
	ctx, cancel := cloudContext()
	defer cancel()
	synced, err := w.cloudService().Sync(ctx)
	for _, p := range synced {
		fmt.Fprintln(w.Stdout, p)
	}
	if err != nil {
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("Synced %d %s.", len(synced), plural(len(synced), "environment", "environments")))
	return 0
}

func (w Workspace) cloudShare(argv []string) int {
	if len(argv) != 1 {
		return w.usageError("cloud share <org>")
	}
	ctx, cancel := cloudContext()
	defer cancel()
	shared, err := w.cloudService().Share(ctx, argv[0])
	if err != nil {
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("Shared the keys of %d %s with every verified member, device, and token that may use them.",
		shared, plural(shared, "environment", "environments")))
	return 0
}

func (w Workspace) cloudRotate(argv []string) int {
	a, err := parseArgs(argv, nil, []string{"accept-removed"}, false)
	if err != nil || len(a.positional) != 1 {
		return w.usageError("cloud rotate <org/project/env> [--accept-removed]")
	}
	path, err := cloud.ParsePath(a.positional[0], false)
	if err != nil {
		return w.cloudFail(err)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	epoch, err := w.cloudService().Rotate(ctx, path.Org, path.Project, path.Env, a.flags["accept-removed"])
	if err != nil {
		return w.cloudFail(err)
	}
	w.status().Success(fmt.Sprintf("%s is at epoch %d. Its values were encrypted again under the new key, signed by this device.", path, epoch))
	if a.flags["accept-removed"] {
		w.status().Warn("What a former member had signed was taken as it was. If a value may have changed since they left, check it and store it again.")
	}
	return 0
}

// cloudStatus shows when each value of an environment was written and
// which devices and tokens have fetched it since.
func (w Workspace) cloudStatus(argv []string) int {
	if len(argv) != 1 {
		return w.usageError("cloud status <org/project/env>")
	}
	path, err := cloud.ParsePath(argv[0], false)
	if err != nil {
		return w.cloudFail(err)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	status, err := w.cloudService().EnvironmentStatus(ctx, path)
	if err != nil {
		return w.cloudFail(err)
	}
	const layout = "2006-01-02 15:04"
	out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(out, "SECRET\tVERSION\tWRITTEN\tPREVIOUS VALUE WORKS UNTIL")
	for _, s := range status.Secrets {
		until := "-"
		if !s.TransitionUntil.IsZero() {
			until = s.TransitionUntil.Local().Format(layout)
		}
		fmt.Fprintf(out, "%s\t%d\t%s\t%s\n", s.Name, s.Version, s.WrittenAt.Local().Format(layout), until)
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "DEVICE OR TOKEN\tLAST SYNC\tSTATE")
	behind := 0
	for _, r := range status.Readers {
		state := "has every current value"
		switch {
		case len(r.Stale) > 0:
			state = "stale: its value of " + strings.Join(r.Stale, ", ") + " is past its transition"
		case len(r.Behind) > 0:
			state = "behind on " + strings.Join(r.Behind, ", ")
		}
		if len(r.Behind) > 0 {
			behind++
		}
		fmt.Fprintf(out, "%s\t%s\t%s\n", r.Name(), r.LastFetch.Local().Format(layout), state)
	}
	out.Flush()
	if behind == 0 {
		w.status().Success(fmt.Sprintf("Every device and token that fetched %s has its current values.", path))
	} else {
		w.status().Warn(fmt.Sprintf("%d of %d have not fetched %s since a value changed. A device syncs when it next runs a command while online.",
			behind, len(status.Readers), path))
	}
	w.status().Info("This shows what reached each device. A process started before the change keeps the old value until it is restarted.")
	return 0
}

// cloudRotation shows and updates guided rotation: what a removed member or
// a revoked token could read, and which of it still has the value they knew.
func (w Workspace) cloudRotation(argv []string) int {
	const usage = "cloud rotation <org> [--all] | accept <org/project/env/name>"
	a, err := parseArgs(argv, nil, []string{"all"}, false)
	if err != nil || len(a.positional) == 0 {
		return w.usageError(usage)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	s := w.cloudService()
	if a.positional[0] == "accept" {
		if len(a.positional) != 2 || a.flags["all"] {
			return w.usageError(usage)
		}
		path, err := cloud.ParsePath(a.positional[1], true)
		if err != nil {
			return w.cloudFail(err)
		}
		if _, err := s.AcceptRotation(ctx, path); err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("Recorded that %s keeps its value.", path))
		w.status().Warn("Whoever left may still know it.")
		return 0
	}
	if len(a.positional) != 1 {
		return w.usageError(usage)
	}
	org := a.positional[0]
	tasks, err := s.Rotation(ctx, org)
	if err != nil {
		return w.cloudFail(err)
	}
	pending := 0
	out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
	for _, t := range tasks {
		if t.Pending() == 0 && !a.flags["all"] {
			continue
		}
		pending += t.Pending()
		fmt.Fprintf(out, "%s, %s: %s could read %d %s; %d still to replace.\n", t.Created.Format("2006-01-02"), t.Reason, t.Subject,
			len(t.Items), plural(len(t.Items), "secret", "secrets"), t.Pending())
		for _, i := range t.Items {
			if i.Status == cloud.RotationPending || a.flags["all"] {
				fmt.Fprintf(out, "  %s\t%s\n", i.Path, i.Status)
			}
		}
	}
	out.Flush()
	if pending == 0 {
		w.status().Success(fmt.Sprintf("Nothing in %s is waiting for a new value.", org))
		return 0
	}
	w.status().Warn(fmt.Sprintf("%d %s still %s a value that someone who left may know.", pending, plural(pending, "secret", "secrets"), plural(pending, "has", "have")))
	w.status().Info("Replace each at its provider and store it with `envrune cloud set <path>`, or use `--generate` for a value you make up.")
	w.status().Info("`envrune cloud rotation accept <path>` records that one stays as it is.")
	return 0
}

func (w Workspace) cloudToken(argv []string) int {
	const usage = "cloud token create <org> --scope <s[,s]> [--name <name>] [--expires 90d] | revoke <id>"
	a, err := parseArgs(argv, []string{"scope", "name", "expires"}, nil, false)
	if err != nil || len(a.positional) != 2 {
		return w.usageError(usage)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	s := w.cloudService()
	switch a.positional[0] {
	case "create":
		scope := splitScope(a.options["scope"])
		ttl, err := parseDays(a.options["expires"], 90*24*time.Hour)
		if len(scope) == 0 || err != nil {
			return w.usageError(usage)
		}
		name := a.options["name"]
		if name == "" {
			name = "ci"
		}
		token, err := s.CreateToken(ctx, a.positional[1], name, scope, ttl)
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Warn("Store this token as a CI secret, such as ENVRUNE_TOKEN. It is shown only once.")
		fmt.Fprintf(w.Stdout, "\n%s\n\n", token)
		w.status().Info("It decrypts " + strings.Join(scope, ", ") + " until " + time.Now().Add(ttl).Format("2006-01-02") + ".")
		return 0
	case "revoke":
		if err := s.RevokeToken(ctx, a.positional[1]); err != nil {
			return w.cloudFail(err)
		}
		w.status().Success("Revoked " + a.positional[1] + ".")
		w.status().Warn("It held environment keys: rotate those environments with `envrune cloud rotate`, and replace the values it read (`envrune cloud rotation <org>`).")
		return 0
	}
	return w.usageError(usage)
}

// parseDays accepts Go durations and whole days, such as 90d.
func parseDays(raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	if days, ok := strings.CutSuffix(raw, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, errUsage
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, errUsage
	}
	return d, nil
}
