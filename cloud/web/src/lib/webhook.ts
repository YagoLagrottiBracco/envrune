import { createHmac } from "node:crypto";
import { lookup } from "node:dns/promises";
import net from "node:net";

// Sending an organization's events to the address it named
// (docs/cloud-operations.md). An event is an audit entry: names, never a
// value. The receiver tells a real one by its signature.

/** The header's value: the HMAC-SHA256 of the body with the webhook's secret. */
export function sign(secret: Uint8Array, body: string): string {
  return "sha256=" + createHmac("sha256", secret).update(body).digest("hex");
}

/** Addresses that are this machine, a private network, or not routable. */
export function isPrivateAddress(address: string): boolean {
  if (net.isIPv4(address)) {
    const [a, b] = address.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a >= 224;
  }
  const lower = address.toLowerCase();
  if (lower.startsWith("::ffff:")) {
    return isPrivateAddress(lower.slice(7));
  }
  return lower === "::" || lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80");
}

/**
 * Whether an address may be sent to. A webhook's address is chosen by an
 * organization's admin, and the request comes from this server, so it must
 * not be a way to reach what only this server can: HTTPS to a public
 * address, unless whoever runs the server allowed private ones for
 * receivers on their own network (ENVRUNE_WEBHOOK_ALLOW_PRIVATE=1).
 */
export async function allowedTarget(url: string, allowPrivate: boolean): Promise<string | null> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "the address is not valid";
  }
  if (allowPrivate) {
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? null : "the address must use https";
  }
  if (parsed.protocol !== "https:") {
    return "the address must use https";
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  const addresses = net.isIP(host) ? [host] : (await lookup(host, { all: true }).catch(() => [])).map((a) => a.address);
  if (addresses.length === 0) {
    return "the address does not resolve";
  }
  return addresses.some(isPrivateAddress) ? "the address is on a private network" : null;
}

export interface PendingEvent {
  id: number;
  payload: { action: string; [field: string]: unknown };
  url: string;
  secret: string; // base64
}

/** Sends one event and returns why it failed, or null. */
export async function send(event: PendingEvent, allowPrivate: boolean): Promise<string | null> {
  const refused = await allowedTarget(event.url, allowPrivate);
  if (refused) {
    return refused;
  }
  const body = JSON.stringify(event.payload);
  try {
    const response = await fetch(event.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "user-agent": "envrune-cloud",
        "x-envrune-event": event.payload.action,
        "x-envrune-signature": sign(Buffer.from(event.secret, "base64"), body),
      },
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(10_000),
    });
    return response.status >= 200 && response.status < 300 ? null : `the receiver answered ${response.status}`;
  } catch {
    return "the receiver could not be reached";
  }
}
