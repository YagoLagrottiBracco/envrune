package cli

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/YagoLagrottiBracco/envrune/internal/domain"
	"github.com/YagoLagrottiBracco/envrune/internal/dotenv"
	"github.com/YagoLagrottiBracco/envrune/internal/project"
)

// templateSuffixes mark dotenv files that hold placeholders meant to be
// committed, such as .env.example. migrate leaves them alone.
var templateSuffixes = []string{".example", ".sample", ".template", ".dist", ".defaults"}

// migration is everything `envrune migrate` will do, planned before
// anything is written.
type migration struct {
	projects  []*migrationProject
	templates []string
	shared    []sharedValue
}

type migrationProject struct {
	dir        string
	name       string
	configPath string
	exists     bool // envrune.yml was already there
	files      []dotenvFile
	vars       []*migrationVar
}

type dotenvFile struct {
	path        string
	environment string
	count       int
}

type migrationVar struct {
	project     *migrationProject
	environment string
	variable    string
	value       []byte
	sum         [32]byte
	ref         domain.Reference
	stored      bool // the vault already holds this value under ref
	keepLink    bool // envrune.yml already links the variable
	conflict    bool // ref exists in the vault with another value
}

// sharedValue is one value that several projects use, which migrate can
// store once under one reference.
type sharedValue struct {
	ref    domain.Reference
	vars   []*migrationVar
	stored bool // the vault already holds the value under ref
}

// migrate imports the .env files of a project, and of its sibling folders
// with --siblings, into the vault and links them in envrune.yml. It shows
// the whole plan, without values, and asks before writing anything.
func (w Workspace) migrate(argv []string) int {
	a, err := parseArgs(argv, []string{"env"}, []string{"siblings"}, false)
	if err != nil || len(a.positional) > 1 {
		return w.usageError("migrate [folder] [--siblings] [--env <environment>]")
	}
	root := "."
	if len(a.positional) == 1 {
		root = a.positional[0]
	}
	if root, err = filepath.Abs(root); err != nil {
		return w.fail(err, "The folder is unavailable.")
	}
	defaultEnv := a.options["env"]
	if defaultEnv == "" {
		defaultEnv = "development"
	}
	dirs := []string{root}
	if a.flags["siblings"] {
		dirs = siblingDirs(root)
	}
	status := w.status()
	plan, err := w.planMigration(dirs, defaultEnv)
	defer plan.wipe()
	if err != nil {
		return w.fail(err, "The .env files could not be read.")
	}
	if len(plan.projects) == 0 {
		status.Info("No .env files to migrate were found.")
		return 0
	}
	if w.ReadChoice == nil {
		status.Error("envrune migrate needs a terminal to confirm the plan.")
		return 1
	}
	for i := range plan.shared {
		s := &plan.shared[i]
		names := make([]string, len(s.vars))
		for j, v := range s.vars {
			names[j] = v.project.name + " " + v.variable
		}
		choice, err := w.ReadChoice(fmt.Sprintf("%s have the same value. Store it once as %s? [Y/n]", strings.Join(names, ", "), s.ref))
		if err != nil {
			return w.fail(err, "Migration cancelled.")
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(choice)), "n") {
			s.vars = nil
			continue
		}
		for _, v := range s.vars {
			v.ref, v.stored, v.conflict = s.ref, s.stored, false
		}
	}
	w.printPlan(plan)
	choice, err := w.ReadChoice("Apply this plan? [y/N]")
	if err != nil || !acceptsSetup(choice) {
		status.Info("Nothing was changed.")
		return 0
	}
	if code := w.applyMigration(plan, defaultEnv); code != 0 {
		return code
	}
	w.offerDelete(plan)
	return 0
}

// siblingDirs returns root and the folders next to it.
func siblingDirs(root string) []string {
	entries, err := os.ReadDir(filepath.Dir(root))
	if err != nil {
		return []string{root}
	}
	dirs := []string{root}
	for _, entry := range entries {
		dir := filepath.Join(filepath.Dir(root), entry.Name())
		if entry.IsDir() && dir != root && !strings.HasPrefix(entry.Name(), ".") {
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// dotenvEnvironment maps a file name to an environment: .env and .env.local
// to the default one, .env.<name> and .env.<name>.local to <name>. It
// returns "" for files that are not dotenv files or are templates.
func dotenvEnvironment(name, defaultEnv string) (environment string, template bool) {
	if name != ".env" && !strings.HasPrefix(name, ".env.") {
		return "", false
	}
	for _, suffix := range templateSuffixes {
		if strings.HasSuffix(name, suffix) {
			return "", true
		}
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(name, ".env"), ".")
	if rest == "" || rest == "local" {
		return defaultEnv, false
	}
	return strings.TrimSuffix(rest, ".local"), false
}

func (w Workspace) planMigration(dirs []string, defaultEnv string) (*migration, error) {
	plan := &migration{}
	existing := map[[32]byte]domain.Reference{}
	secrets, err := w.Session.Secrets("")
	if err != nil {
		return plan, err
	}
	stored := map[domain.Reference][32]byte{}
	for _, s := range secrets {
		sum := sha256.Sum256(s.Value)
		wipe(s.Value)
		ref := domain.Reference(s.Name)
		stored[ref] = sum
		if _, ok := existing[sum]; !ok {
			existing[sum] = ref
		}
	}
	for _, dir := range dirs {
		p, err := planProject(dir, defaultEnv, plan)
		if err != nil {
			return plan, err
		}
		if p == nil {
			continue
		}
		for _, v := range p.vars {
			if !v.keepLink {
				if ref, ok := existing[v.sum]; ok {
					v.ref, v.stored = ref, true // the same value is already in the vault
					continue
				}
			}
			// A reference that already holds another value is never
			// overwritten: the vault may be newer than the .env file.
			if sum, ok := stored[v.ref]; ok {
				v.stored, v.conflict = sum == v.sum, sum != v.sum
			}
		}
		plan.projects = append(plan.projects, p)
	}
	plan.shared = findShared(plan.projects, stored)
	return plan, nil
}

// planProject reads the dotenv files of one folder. It returns nil when the
// folder has none.
func planProject(dir, defaultEnv string, plan *migration) (*migrationProject, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			names = append(names, entry.Name())
		}
	}
	// Plain files before .local ones, so local overrides win as in dotenv.
	sort.Slice(names, func(i, j int) bool {
		li, lj := strings.HasSuffix(names[i], ".local"), strings.HasSuffix(names[j], ".local")
		if li != lj {
			return lj
		}
		return names[i] < names[j]
	})
	p := &migrationProject{dir: dir, configPath: filepath.Join(dir, "envrune.yml"), name: slug(filepath.Base(dir))}
	var config project.Config
	if loaded, err := project.Load(p.configPath); err == nil {
		config, p.exists, p.name = loaded, true, loaded.Project
	} else if _, statErr := os.Stat(p.configPath); statErr == nil {
		return nil, fmt.Errorf("%s: %w", p.configPath, err)
	}
	byKey := map[string]*migrationVar{}
	for _, name := range names {
		environment, template := dotenvEnvironment(name, defaultEnv)
		if template {
			plan.templates = append(plan.templates, filepath.Join(dir, name))
		}
		if environment == "" {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		parsed, err := dotenv.ParseCommon(raw)
		wipe(raw)
		if err != nil {
			return nil, fmt.Errorf("%s %w", path, err)
		}
		file := dotenvFile{path: path, environment: environment}
		for _, entry := range parsed {
			if len(entry.Value) == 0 {
				continue // nothing to store; the variable stays unset
			}
			file.count++
			key := environment + "\x00" + entry.Name
			if previous, ok := byKey[key]; ok {
				wipe(previous.value)
				previous.value, previous.sum = entry.Value, sha256.Sum256(entry.Value)
				continue
			}
			v := &migrationVar{project: p, environment: environment, variable: entry.Name, value: entry.Value, sum: sha256.Sum256(entry.Value)}
			if ref, ok := config.Environments[environment][entry.Name]; ok {
				v.ref, v.keepLink = ref, true
			} else {
				v.ref = domain.Reference(suggestReference(p.name, entry.Name, environment))
			}
			byKey[key] = v
			p.vars = append(p.vars, v)
		}
		p.files = append(p.files, file)
	}
	if len(p.files) == 0 {
		return nil, nil
	}
	return p, nil
}

// findShared groups values that more than one project uses. stored holds
// the checksum of each reference already in the vault.
func findShared(projects []*migrationProject, stored map[domain.Reference][32]byte) []sharedValue {
	groups := map[[32]byte][]*migrationVar{}
	var order [][32]byte
	for _, p := range projects {
		for _, v := range p.vars {
			if v.keepLink {
				continue
			}
			if _, ok := groups[v.sum]; !ok {
				order = append(order, v.sum)
			}
			groups[v.sum] = append(groups[v.sum], v)
		}
	}
	var out []sharedValue
	for _, sum := range order {
		vars := groups[sum]
		projectsUsing := map[*migrationProject]bool{}
		for _, v := range vars {
			projectsUsing[v.project] = true
		}
		if len(projectsUsing) < 2 {
			continue
		}
		name, environment := vars[0].variable, vars[0].environment
		for _, v := range vars[1:] {
			if v.environment != environment {
				environment = ""
			}
		}
		ref := domain.Reference("shared." + slug(name))
		if environment != "" {
			ref += domain.Reference("." + slug(environment))
		}
		if vars[0].stored {
			ref = vars[0].ref // already in the vault under a name
		}
		if sum, ok := stored[ref]; ok && sum != vars[0].sum {
			continue // the name is taken by another value
		}
		_, inVault := stored[ref]
		out = append(out, sharedValue{ref: ref, vars: vars, stored: inVault})
	}
	return out
}

func (w Workspace) printPlan(plan *migration) {
	out := w.Stdout
	fmt.Fprintln(out, "\nMigration plan (values are not shown):")
	newRefs, reused, conflicts := 0, 0, 0
	seen := map[domain.Reference]bool{}
	for _, p := range plan.projects {
		state := "envrune.yml exists"
		if !p.exists {
			state = "creates envrune.yml"
		}
		fmt.Fprintf(out, "\n  %s (%s, project %q)\n", p.dir, state, p.name)
		for _, f := range p.files {
			fmt.Fprintf(out, "    %s → %s: %d %s\n", filepath.Base(f.path), f.environment, f.count, plural(f.count, "variable", "variables"))
		}
		for _, v := range p.vars {
			note := ""
			switch {
			case v.conflict:
				note = " (skipped: the vault holds another value; it is kept)"
				conflicts++
			case v.keepLink && v.stored:
				note = " (already linked and stored)"
			case v.keepLink:
				note = " (already linked; the value is stored)"
			case v.stored:
				note = " (already in the vault)"
			}
			fmt.Fprintf(out, "      %-28s %-12s → %s%s\n", v.variable, v.environment, v.ref, note)
			if v.conflict || seen[v.ref] {
				continue
			}
			seen[v.ref] = true
			if v.stored {
				reused++
			} else {
				newRefs++
			}
		}
	}
	fmt.Fprintf(out, "\n  Vault: %d new %s, %d already stored.\n", newRefs, plural(newRefs, "reference", "references"), reused)
	if conflicts > 0 {
		fmt.Fprintf(out, "  %d %s skipped because the vault holds another value under that reference. Check them with `envrune info <reference>`.\n", conflicts, plural(conflicts, "variable is", "variables are"))
	}
	fmt.Fprintln(out, "  .gitignore: .env and .env.* will be ignored in each folder.")
	for _, t := range plan.templates {
		fmt.Fprintf(out, "  Left alone: %s (a template).\n", t)
	}
	fmt.Fprintln(out)
}

func (w Workspace) applyMigration(plan *migration, defaultEnv string) int {
	status := w.status()
	stored := map[domain.Reference]bool{}
	for _, p := range plan.projects {
		if !p.exists {
			environments := map[string]map[string]domain.Reference{defaultEnv: {}}
			for _, f := range p.files {
				environments[f.environment] = map[string]domain.Reference{}
			}
			config := project.Config{Version: 1, Project: p.name, DefaultEnv: defaultEnv, Environments: environments}
			if err := project.WriteAtomic(p.configPath, config); err != nil {
				return w.fail(err, "Could not create "+p.configPath+".")
			}
		}
		for _, v := range p.vars {
			if v.conflict {
				continue
			}
			if !v.stored && !stored[v.ref] {
				if err := w.Session.Set(v.ref.String(), v.value); err != nil {
					return w.fail(err, "Could not store "+v.ref.String()+".")
				}
				stored[v.ref] = true
			}
			if !v.keepLink {
				if err := w.Session.Link(p.configPath, v.environment, v.variable, v.ref.String()); err != nil {
					return w.fail(err, "Could not link "+v.variable+".")
				}
			}
		}
		if err := ignoreDotenv(p.dir); err != nil {
			status.Warn(fmt.Sprintf("Could not update %s: %v. Add .env and .env.* to it yourself.", filepath.Join(p.dir, ".gitignore"), err))
		}
		status.Success(fmt.Sprintf("Migrated %s: %d variables in %s.", p.dir, len(p.vars), filepath.Base(p.configPath)))
		for _, f := range p.files {
			if tracked(f.path) {
				status.Warn(fmt.Sprintf("%s is committed to Git, so its values are in the history. Run `envrune scan` and rotate them.", f.path))
			}
		}
	}
	return 0
}

// ignoreDotenv makes sure .gitignore in dir ignores dotenv files but keeps
// .env.example.
func ignoreDotenv(dir string) error {
	path := filepath.Join(dir, ".gitignore")
	current, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	have := map[string]bool{}
	for _, line := range strings.Split(string(current), "\n") {
		have[strings.TrimSpace(line)] = true
	}
	var missing []string
	for _, line := range []string{".env", ".env.*", "!.env.example"} {
		if !have[line] {
			missing = append(missing, line)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	var b bytes.Buffer
	b.Write(current)
	if len(current) > 0 && !bytes.HasSuffix(current, []byte("\n")) {
		b.WriteByte('\n')
	}
	b.WriteString("# Local environment files; values live in the EnvRune vault.\n")
	b.WriteString(strings.Join(missing, "\n") + "\n")
	return os.WriteFile(path, b.Bytes(), 0644)
}

// tracked reports whether Git tracks path.
func tracked(path string) bool {
	cmd := exec.Command("git", "-C", filepath.Dir(path), "ls-files", "--error-unmatch", filepath.Base(path))
	return cmd.Run() == nil
}

func (w Workspace) offerDelete(plan *migration) {
	var files []string
	for _, p := range plan.projects {
		for _, f := range p.files {
			files = append(files, f.path)
		}
	}
	choice, err := w.ReadChoice(fmt.Sprintf("Delete the %d migrated .env %s now? Their values are in the vault. [y/N]", len(files), plural(len(files), "file", "files")))
	status := w.status()
	if err != nil || !acceptsSetup(choice) {
		status.Info("The .env files were kept. Delete them once your commands work with `envrune run`.")
		return
	}
	for _, path := range files {
		if err := os.Remove(path); err != nil {
			status.Warn(fmt.Sprintf("Could not delete %s: %v", path, err))
		}
	}
	status.Success("Deleted the migrated .env files.")
}

func (m *migration) wipe() {
	for _, p := range m.projects {
		for _, v := range p.vars {
			wipe(v.value)
		}
	}
}
