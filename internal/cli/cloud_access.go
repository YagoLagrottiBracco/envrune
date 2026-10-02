package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"
)

const cloudAccessUsage = "cloud access request <org/project/env> --for <4h> [--reason <text>] | list <org> | approve <org> <id> | deny <org> <id> | end <org> <id>"

// cloudAccess asks for, decides, and ends access for a limited time
// (docs/cloud-operations.md).
func (w Workspace) cloudAccess(argv []string) int {
	a, err := parseArgs(argv, []string{"for", "reason"}, nil, false)
	if err != nil || len(a.positional) < 2 {
		return w.usageError(cloudAccessUsage)
	}
	ctx, cancel := cloudContext()
	defer cancel()
	s := w.cloudService()
	action, org := a.positional[0], a.positional[1]
	switch {
	case action == "request" && len(a.positional) == 2:
		// org/project/environment, or org/project/* for every environment.
		parts := strings.SplitN(org, "/", 2)
		duration, err := parseDays(a.options["for"], 0)
		if len(parts) != 2 || strings.Count(parts[1], "/") != 1 || err != nil || duration <= 0 {
			return w.usageError(cloudAccessUsage)
		}
		id, err := s.RequestAccess(ctx, parts[0], []string{parts[1]}, duration, a.options["reason"])
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("Asked for %s in %s for %s. An owner or admin approves it with:", parts[1], parts[0], a.options["for"]))
		fmt.Fprintf(w.Stdout, "\n    envrune cloud access approve %s %s\n\n", parts[0], id)
		return 0
	case action == "list" && len(a.positional) == 2:
		grants, err := s.AccessList(ctx, org)
		if err != nil {
			return w.cloudFail(err)
		}
		if len(grants) == 0 {
			w.status().Info("No requests for access in " + org + ".")
			return 0
		}
		out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(out, "REQUEST\tMEMBER\tASKED FOR\tSTATE\tREASON")
		open := 0
		for _, g := range grants {
			state := g.Status
			switch {
			case g.Status == "pending":
				state = fmt.Sprintf("waiting, for %s", time.Duration(g.Minutes)*time.Minute)
			case g.Expired():
				state = "time is up: refused by the server, waiting to be ended"
			case g.Status == "approved":
				state = "until " + g.ExpiresAt.Local().Format("2006-01-02 15:04")
			case g.Open():
				state = "ended, what was fetched is not listed yet"
			}
			if g.Open() {
				open++
			}
			fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\n", g.ID, g.UserID, strings.Join(g.Scope, ","), state, g.Reason)
		}
		out.Flush()
		if open > 0 {
			w.status().Warn(fmt.Sprintf("%d %s to be ended with `envrune cloud access end %s <request>`: it signs the scope back and starts new keys.", open, plural(open, "waits", "wait"), org))
		}
		return 0
	case action == "approve" && len(a.positional) == 3:
		until, err := s.ApproveAccess(ctx, org, a.positional[2])
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Success("Approved until " + until.Local().Format("2006-01-02 15:04") + ". The server stops serving it then, by itself.")
		w.status().Info(fmt.Sprintf("Afterwards, `envrune cloud access end %s %s` signs the scope back and starts new keys.", org, a.positional[2]))
		return 0
	case action == "deny" && len(a.positional) == 3:
		if err := s.DenyAccess(ctx, org, a.positional[2]); err != nil {
			return w.cloudFail(err)
		}
		w.status().Success("Denied.")
		return 0
	case action == "end" && len(a.positional) == 3:
		h, err := s.EndAccess(ctx, org, a.positional[2])
		if err != nil {
			w.handover(org, "the member", h)
			return w.cloudFail(err)
		}
		w.status().Success("The access has ended, and the member's scope is what it was before.")
		w.handover(org, "the member", h)
		w.status().Info(fmt.Sprintf("What they fetched meanwhile is listed to replace: `envrune cloud rotation %s`.", org))
		return 0
	}
	return w.usageError(cloudAccessUsage)
}
