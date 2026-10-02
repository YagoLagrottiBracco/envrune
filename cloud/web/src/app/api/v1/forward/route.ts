import { ApiError, authenticated, fromPostgres, notConfigured } from "@/lib/api";
import { missing, proxyIdentity } from "@/lib/env";
import { buildResponse, buildUpstream, ForwardRefused, type Substitution } from "@/lib/forward";
import { openSensitive, type SensitiveRow } from "@/lib/sensitive";
import { adminClient } from "@/lib/supabase/server";

// Any method: forward a member's request to a service, with the sensitive
// secrets it names put in place of their placeholders (docs/managed-keys.md).
// The member's envrune sends, next to the request's own body:
//
//   Authorization      the member's session, as for every other route
//   X-EnvRune-Device   the member's device
//   X-EnvRune-Target   the address the program was calling
//   X-EnvRune-Headers  the program's headers, as base64 of JSON [[name, value], ...]
//   X-EnvRune-Secrets  base64 of JSON [{ environment_id, name, placeholder }, ...]
//
// The answer is the service's own, marked `X-EnvRune-Forward: upstream`. When
// this server refuses or cannot reach the service, it answers with JSON and
// `X-EnvRune-Forward: refused`, so the two cannot be mistaken.

export const maxDuration = 60;

interface Named {
  environment_id: string;
  name: string;
  placeholder: string;
}

function refused(status: number, message: string): Response {
  return Response.json({ error: message }, { status, headers: { "x-envrune-forward": "refused" } });
}

function decoded<T>(request: Request, header: string): T {
  try {
    return JSON.parse(Buffer.from(request.headers.get(header) ?? "", "base64").toString("utf8")) as T;
  } catch {
    throw new ForwardRefused(400, `${header} is not valid`);
  }
}

async function forward(request: Request): Promise<Response> {
  if (missing().length > 0) {
    return notConfigured();
  }
  try {
    const identity = proxyIdentity();
    if (!identity) {
      throw new ForwardRefused(404, "this server has no proxy identity, so it does not take sensitive secrets");
    }
    const { client } = await authenticated(request);
    const device = request.headers.get("x-envrune-device") ?? "";
    const target = request.headers.get("x-envrune-target") ?? "";
    const headers = decoded<[string, string][]>(request, "x-envrune-headers");
    const named = decoded<Named[]>(request, "x-envrune-secrets");
    if (!Array.isArray(headers) || !Array.isArray(named) || named.length === 0 || named.length > 16) {
      throw new ForwardRefused(400, "name 1 to 16 sensitive secrets and the request's headers");
    }
    let host: string;
    try {
      host = new URL(target).hostname.toLowerCase();
    } catch {
      throw new ForwardRefused(400, "the address to forward to is not valid");
    }
    const ask = async (s: Named, record: boolean) => {
      const { error } = await client.rpc("sensitive_forward", {
        p_env: s.environment_id,
        p_name: s.name,
        p_device: device,
        p_host: host,
        p_record: record,
      });
      if (error) {
        throw fromPostgres(error);
      }
    };

    // As the member: may they use each secret, from this device?
    const substitutions: Substitution[] = [];
    for (const s of named) {
      await ask(s, false);
      // As the server: the ciphertext, which no member is ever sent.
      const { data, error } = await adminClient().rpc("sensitive_for_proxy", { p_env: s.environment_id, p_name: s.name });
      if (error || !data) {
        throw new ForwardRefused(404, `no sensitive secret ${s.name} in that environment`);
      }
      const content = await openSensitive(identity, data as SensitiveRow);
      substitutions.push({ placeholder: s.placeholder, value: content.value, hosts: content.hosts });
    }
    const body = request.body ? new Uint8Array(await request.arrayBuffer()) : null;
    // Refuses a host that a secret does not allow, before anything is sent.
    const upstream = buildUpstream({ method: request.method, target, headers, body }, substitutions);
    for (const s of named) {
      await ask(s, true);
    }
    let response: Response;
    try {
      response = await fetch(upstream.url, { ...upstream.init, signal: AbortSignal.timeout(55_000) });
    } catch {
      throw new ForwardRefused(502, `${host} could not be reached from the server`);
    }
    return await buildResponse(response, substitutions);
  } catch (error) {
    if (error instanceof ForwardRefused || error instanceof ApiError) {
      return refused(error.status, error.message);
    }
    // Never the error itself: it could describe a request that holds a value.
    console.error("forwarding a request failed");
    return refused(500, "the request could not be forwarded");
  }
}

export { forward as GET, forward as POST, forward as PUT, forward as PATCH, forward as DELETE, forward as HEAD, forward as OPTIONS };
