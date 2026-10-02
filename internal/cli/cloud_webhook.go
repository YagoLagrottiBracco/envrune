package cli

import (
	"fmt"
	"text/tabwriter"
)

const cloudWebhookUsage = "cloud webhook set <org> <https address> | show <org> | clear <org>"

// cloudWebhook manages the address an organization's events are sent to
// (docs/cloud-operations.md).
func (w Workspace) cloudWebhook(argv []string) int {
	ctx, cancel := cloudContext()
	defer cancel()
	s := w.cloudService()
	switch {
	case len(argv) == 3 && argv[0] == "set":
		secret, err := s.SetWebhook(ctx, argv[1], argv[2])
		if err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(fmt.Sprintf("Events of %s are now sent to %s.", argv[1], argv[2]))
		w.status().Warn("Give this secret to the receiver. It is shown only once.")
		fmt.Fprintf(w.Stdout, "\n%s\n\n", secret)
		w.status().Info("Each request carries X-EnvRune-Signature: sha256=<HMAC-SHA256 of the body with this secret, in hex>. Check it before trusting an event.")
		return 0
	case len(argv) == 2 && argv[0] == "show":
		hook, err := s.WebhookStatus(ctx, argv[1])
		if err != nil {
			return w.cloudFail(err)
		}
		if hook == nil {
			w.status().Info(argv[1] + " has no webhook.")
			return 0
		}
		out := tabwriter.NewWriter(w.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(out, "address\t%s\n", hook.URL)
		if hook.LastDeliveredAt != nil {
			fmt.Fprintf(out, "last delivered\t%s\n", hook.LastDeliveredAt.Local().Format("2006-01-02 15:04"))
		}
		fmt.Fprintf(out, "waiting\t%d\n", hook.Waiting)
		out.Flush()
		if hook.Failures > 0 {
			w.status().Warn(fmt.Sprintf("The last %d %s failed: %s. An event is tried eight times.", hook.Failures, plural(hook.Failures, "attempt", "attempts"), hook.LastError))
			return 1
		}
		return 0
	case len(argv) == 2 && argv[0] == "clear":
		if err := s.ClearWebhook(ctx, argv[1]); err != nil {
			return w.cloudFail(err)
		}
		w.status().Success(argv[1] + " has no webhook now. Events that were waiting are dropped.")
		return 0
	}
	return w.usageError(cloudWebhookUsage)
}
