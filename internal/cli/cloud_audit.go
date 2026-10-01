package cli

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/YagoLagrottiBracco/envrune/internal/cloud"
)

const cloudAuditUsage = "cloud audit export <org> [--output <file>] | verify <file> [--since <older-file>]"

// cloudAudit exports an organization's audit log, verified, and verifies
// exports again later. Entries name people, devices, and secrets, never a
// value.
func (w Workspace) cloudAudit(argv []string) int {
	a, err := parseArgs(argv, []string{"output", "since"}, nil, false)
	if err != nil || len(a.positional) != 2 {
		return w.usageError(cloudAuditUsage)
	}
	_, hasOutput := a.options["output"]
	_, hasSince := a.options["since"]
	switch {
	case a.positional[0] == "export" && !hasSince:
		return w.cloudAuditExport(a.positional[1], a.options["output"])
	case a.positional[0] == "verify" && !hasOutput:
		return w.cloudAuditVerify(a.positional[1], a.options["since"])
	}
	return w.usageError(cloudAuditUsage)
}

func (w Workspace) cloudAuditExport(org, output string) int {
	ctx, cancel := cloudContext()
	defer cancel()
	export, err := w.cloudService().Audit(ctx, org)
	if err != nil {
		return w.cloudFail(err)
	}
	var out io.Writer = w.Stdout
	if output != "" {
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return w.fail(err, "The file could not be written.")
		}
		defer file.Close()
		out = file
	}
	if err := cloud.WriteAudit(out, export.Entries); err != nil {
		return w.fail(err, "The file could not be written.")
	}
	w.status().Success(fmt.Sprintf("Verified %s of %s's audit log: none was edited or removed.", auditCount(export.Entries), org))
	if export.Previous != nil {
		w.status().Info(fmt.Sprintf("It still holds entry #%d, which this device verified last time.", export.Previous.ID))
	} else {
		w.status().Info("This device now remembers the last entry, and checks that later exports still hold it.")
	}
	w.status().Info("Head: " + export.Head.String())
	return 0
}

// cloudAuditVerify checks an export again, without the server or the vault.
func (w Workspace) cloudAuditVerify(path, since string) int {
	entries, code := w.readAudit(path)
	if code != 0 {
		return code
	}
	head, err := cloud.VerifyAudit(entries)
	if err != nil {
		return w.cloudFail(err)
	}
	if since != "" {
		older, code := w.readAudit(since)
		if code != 0 {
			return code
		}
		if _, err := cloud.VerifyAudit(older); err != nil {
			return w.cloudFail(fmt.Errorf("%s: %w", since, err))
		}
		if err := cloud.AuditContinues(older, entries); err != nil {
			return w.cloudFail(err)
		}
	}
	w.status().Success(fmt.Sprintf("%s: %s, from %s to %s; none was edited or removed.", path, auditCount(entries), auditDay(entries[0]), auditDay(entries[len(entries)-1])))
	if since != "" {
		w.status().Info("It holds every entry of " + since + ", unchanged.")
	} else {
		w.status().Info("To know that it is the same log as an older export, pass that file with --since.")
	}
	w.status().Info("Head: " + head.String())
	return 0
}

func (w Workspace) readAudit(path string) ([]cloud.AuditEntry, int) {
	file, err := os.Open(path)
	if err != nil {
		return nil, w.fail(err, "The file could not be read.")
	}
	defer file.Close()
	entries, err := cloud.ReadAudit(file)
	if err != nil {
		return nil, w.cloudFail(fmt.Errorf("%s: %w", path, err))
	}
	return entries, 0
}

func auditCount(entries []cloud.AuditEntry) string {
	return fmt.Sprintf("%d %s", len(entries), plural(len(entries), "entry", "entries"))
}

func auditDay(e cloud.AuditEntry) string {
	at, err := time.Parse(time.RFC3339Nano, e.At)
	if err != nil {
		return e.At
	}
	return at.UTC().Format("2006-01-02")
}
