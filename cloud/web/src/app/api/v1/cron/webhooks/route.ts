import { notConfigured } from "@/lib/api";
import { deliverWebhooks } from "@/lib/deliver";
import { missing } from "@/lib/env";

// GET: send the events still waiting. Events go out right after they
// happen; this is for the ones whose receiver was down. Call it from any
// scheduler, every few minutes, with `Authorization: Bearer <CRON_SECRET>`.
// Without CRON_SECRET set on the server the route is closed.
export async function GET(request: Request): Promise<Response> {
  if (missing().length > 0) {
    return notConfigured();
  }
  const secret = process.env["CRON_SECRET"];
  if (!secret || request.headers.get("authorization") !== `Bearer ${secret}`) {
    return Response.json({ error: "not allowed" }, { status: 401 });
  }
  return Response.json({ sent: await deliverWebhooks(100) });
}
