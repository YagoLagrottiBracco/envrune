import https from "node:https";
import { Readable } from "node:stream";

// Sending a request with a client certificate, for services that identify
// their callers that way. The certificate is a sensitive secret like any
// other: sealed to this server, presented only to the hosts its owner
// allowed (docs/managed-keys.md). `fetch` cannot present one, so this sends
// the request with node:https and returns the same kind of Response.

export interface ClientCertificate {
  certificate: string;
  key: string;
  /** Authorities to trust instead of the system's; tests pass their own. */
  ca?: string;
}

/** Sends one request, presenting the certificate. It follows no redirect. */
export function sendWithCertificate(
  url: string,
  init: { method?: string; headers?: Headers; body?: Uint8Array | null; signal?: AbortSignal },
  client: ClientCertificate,
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    init.headers?.forEach((value, name) => {
      headers[name] = value;
    });
    const body = init.body && init.body.length > 0 ? Buffer.from(init.body) : null;
    if (body) {
      headers["content-length"] = String(body.length);
    }
    const request = https.request(
      url,
      { method: init.method ?? "GET", headers, cert: client.certificate, key: client.key, ca: client.ca, signal: init.signal },
      (response) => {
        const answer = new Headers();
        for (let i = 0; i + 1 < response.rawHeaders.length; i += 2) {
          answer.append(response.rawHeaders[i], response.rawHeaders[i + 1]);
        }
        const status = response.statusCode ?? 502;
        const empty = status === 204 || status === 304 || init.method === "HEAD";
        if (empty) {
          response.resume();
        }
        resolve(
          new Response(empty ? null : (Readable.toWeb(response) as unknown as ReadableStream<Uint8Array>), {
            status,
            statusText: response.statusMessage,
            headers: answer,
          }),
        );
      },
    );
    request.on("error", reject);
    request.end(body ?? undefined);
  });
}
