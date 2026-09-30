package cli

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/app"
	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/team"
)

const teamUsage = `team init <your-name> | whoami | keygen | members | add <name> <public-key> | remove <name> | set <team.reference> | unset <team.reference> | list`

func (w Workspace) team(argv []string) int {
	if len(argv) == 0 {
		return w.usageError(teamUsage)
	}
	sub, rest := argv[0], argv[1:]
	switch {
	case sub == "whoami" && len(rest) == 0:
		identity, created, err := w.Session.Identity()
		if err != nil {
			return w.fail(err, "The team identity is unavailable.")
		}
		public, err := team.PublicKey(identity)
		if err != nil {
			return w.fail(err, "The team identity is invalid.")
		}
		if created {
			w.status().Info("Created your team identity. Its private key stays in your vault.")
		}
		fmt.Fprintln(w.Stdout, public)
		w.status().Info("Share this public key; a member adds you with `team add <name> <public-key>`.")
		return 0
	case sub == "init" && len(rest) == 1:
		return w.teamInit(rest[0])
	case sub == "members" && len(rest) == 0:
		projectPath, err := w.findProject()
		if err != nil {
			return w.fail(err, "No Envrune project configuration was found.")
		}
		members, err := team.Members(team.Path(projectPath))
		if err != nil {
			return w.fail(err, "The team file is unavailable.")
		}
		for _, m := range members {
			fmt.Fprintf(w.Stdout, "%s %s\n", m.Name, m.PublicKey)
		}
		return 0
	case sub == "add" && len(rest) == 2:
		return w.teamEdit(func(f *team.File) error { return f.AddMember(rest[0], rest[1]) },
			fmt.Sprintf("Added %s. Commit %s so they can use the shared secrets.", rest[0], team.FileName))
	case sub == "remove" && len(rest) == 1:
		code := w.teamEdit(func(f *team.File) error { return f.RemoveMember(rest[0]) },
			fmt.Sprintf("Removed %s from %s.", rest[0], team.FileName))
		if code == 0 {
			w.status().Warn("They may still have old values from Git history or their own copies. Rotate the shared secrets they could read.")
		}
		return code
	case sub == "set" && len(rest) == 1:
		return w.set(rest)
	case sub == "unset" && len(rest) == 1:
		ref, err := domain.ParseReference(rest[0])
		if err != nil {
			return w.fail(err, "")
		}
		return w.teamEdit(func(f *team.File) error { return f.Remove(ref) }, fmt.Sprintf("Removed %s from %s.", rest[0], team.FileName))
	case sub == "list" && len(rest) == 0:
		file, _, err := w.openTeam()
		if err != nil {
			return w.fail(err, "The team file is unavailable.")
		}
		defer file.Close()
		for _, ref := range file.References() {
			fmt.Fprintln(w.Stdout, ref)
		}
		return 0
	}
	return w.usageError(teamUsage)
}

func (w Workspace) teamInit(name string) int {
	projectPath, err := w.findProject()
	if err != nil {
		return w.fail(err, "No Envrune project configuration was found.")
	}
	path := team.Path(projectPath)
	if team.Exists(path) {
		w.status().Error(fmt.Sprintf("%s already exists. Ask a member to add you with your `team whoami` key.", team.FileName))
		return 1
	}
	identity, _, err := w.Session.Identity()
	if err != nil {
		return w.fail(err, "The team identity is unavailable.")
	}
	file, err := team.Create(path, name, identity)
	if err != nil {
		return w.fail(err, "The team file could not be created.")
	}
	file.Close()
	w.status().Success(fmt.Sprintf("Created %s with you (%s) as the only member. Commit it to share secrets under team.*.", team.FileName, name))
	return 0
}

func (w Workspace) openTeam() (*team.File, string, error) {
	projectPath, err := w.findProject()
	if err != nil {
		return nil, "", err
	}
	path := team.Path(projectPath)
	if !team.Exists(path) {
		return nil, "", app.ErrNoTeamFile
	}
	identity, _, err := w.Session.Identity()
	if err != nil {
		return nil, "", err
	}
	file, err := team.Open(path, identity)
	return file, path, err
}

func (w Workspace) teamEdit(change func(*team.File) error, success string) int {
	file, _, err := w.openTeam()
	if err != nil {
		return w.fail(err, "The team file is unavailable.")
	}
	defer file.Close()
	if err := change(file); err != nil {
		return w.fail(err, "The team file could not be changed.")
	}
	if err := file.Save(); err != nil {
		return w.fail(err, "The team file could not be saved.")
	}
	w.status().Success(success)
	return 0
}

func (w Workspace) teamSetValue(rawReference string, value []byte) error {
	ref, err := domain.ParseReference(rawReference)
	if err != nil {
		return err
	}
	file, _, err := w.openTeam()
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Set(ref, value); err != nil {
		return err
	}
	return file.Save()
}

// executeTeamKeygen creates an identity outside any vault, for a CI
// pipeline. The private key goes to stdout so it can be piped into a secret
// store; the public key goes to stderr.
func executeTeamKeygen(stdout io.Writer, status Presenter) int {
	identity, err := team.NewIdentity()
	if err != nil {
		status.Error(describe(err, "The identity could not be created."))
		return 1
	}
	public, _ := team.PublicKey(identity)
	fmt.Fprintln(stdout, identity)
	status.Info("Store the line above as the ENVRUNE_IDENTITY secret of your CI, then add it with:")
	status.Info("envrune team add ci " + public)
	return 0
}

// push copies an environment to a CI provider's secret store.
func (w Workspace) push(argv []string) int {
	const usage = "push github [--env <environment>] [--repo <owner/name>] [--github-env <name>]"
	if len(argv) == 0 || argv[0] != "github" {
		return w.usageError(usage)
	}
	a, err := parseArgs(argv[1:], []string{"env", "repo", "github-env"}, nil, false)
	if err != nil || len(a.positional) != 0 {
		return w.usageError(usage)
	}
	if _, err := exec.LookPath("gh"); err != nil {
		w.status().Error("The GitHub CLI (gh) is required. Install it and run `gh auth login`.")
		return 1
	}
	_, resolved, err := w.resolve(a.options["env"])
	defer wipePairs(resolved.Pairs)
	if err != nil {
		return w.fail(err, "Configured secrets are unavailable.")
	}
	for _, pair := range resolved.Pairs {
		fmt.Fprintln(w.Stdout, pair.Name)
	}
	target := "the current repository"
	if repo := a.options["repo"]; repo != "" {
		target = repo
	}
	if env := a.options["github-env"]; env != "" {
		target += " (environment " + env + ")"
	}
	w.status().Warn(fmt.Sprintf("These %d variables from %s will be stored as GitHub Actions secrets in %s.", len(resolved.Pairs), resolved.Environment, target))
	if !w.confirm() {
		w.status().Error("Confirmation is required.")
		return 1
	}
	for _, pair := range resolved.Pairs {
		args := []string{"secret", "set", pair.Name}
		if repo := a.options["repo"]; repo != "" {
			args = append(args, "--repo", repo)
		}
		if env := a.options["github-env"]; env != "" {
			args = append(args, "--env", env)
		}
		// gh reads the value from standard input, so it never appears in
		// the process list.
		cmd := exec.Command("gh", args...)
		cmd.Stdin = bytes.NewReader(pair.Value)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			w.status().Error(fmt.Sprintf("gh could not store %s: %s", pair.Name, strings.TrimSpace(stderr.String())))
			return 1
		}
		w.status().Success(fmt.Sprintf("Stored %s.", pair.Name))
	}
	return 0
}
