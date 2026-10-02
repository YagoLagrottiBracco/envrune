import "server-only";
import { adminClient } from "./supabase/server";
import { send, type PendingEvent } from "./webhook";

// Sends the events organizations are waiting for. It is called after a
// request that changed something, and by the scheduled route, so an event
// goes out soon after it happens and is tried again if the receiver was
// down. See docs/cloud-operations.md.

/** Whoever runs the server may let webhooks reach their own network. */
const allowPrivate = () => process.env["ENVRUNE_WEBHOOK_ALLOW_PRIVATE"] === "1";

/** Sends up to `limit` waiting events, oldest first, and records each outcome. */
export async function deliverWebhooks(limit = 25): Promise<number> {
  const admin = adminClient();
  const { data, error } = await admin.rpc("webhook_pending", { p_limit: limit });
  if (error || !Array.isArray(data)) {
    return 0;
  }
  let sent = 0;
  for (const event of data as PendingEvent[]) {
    const failure = await send(event, allowPrivate());
    await admin.rpc("webhook_attempted", { p_id: event.id, p_ok: failure === null, p_error: failure ?? "" });
    if (failure === null) {
      sent++;
    }
  }
  return sent;
}
