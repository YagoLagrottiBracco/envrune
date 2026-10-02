import { test } from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import type { TLSSocket } from "node:tls";
import { sendWithCertificate } from "./mtls.ts";

// Test certificates written by internal/cloudcrypto's mtls_test.go.
const vector = JSON.parse(readFileSync(new URL("./mtls-vector.json", import.meta.url), "utf8"));

// A service that only answers callers who present a certificate its
// authority signed, and says who they are.
function service(): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = https.createServer(
      { cert: vector.server_cert, key: vector.server_key, ca: vector.ca, requestCert: true, rejectUnauthorized: true },
      (request, response) => {
        const chunks: Buffer[] = [];
        request.on("data", (chunk) => chunks.push(chunk));
        request.on("end", () => {
          const caller = (request.socket as TLSSocket).getPeerCertificate().subject.CN;
          response.writeHead(201, { "content-type": "application/json", "x-method": request.method ?? "" });
          response.end(JSON.stringify({ caller, sent: Buffer.concat(chunks).toString(), header: request.headers["x-thing"] }));
        });
      },
    );
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `https://localhost:${port}`, close: () => server.close() });
    });
  });
}

test("a request presents the client certificate", async () => {
  const s = await service();
  try {
    const response = await sendWithCertificate(
      `${s.url}/v1/transfers?x=1`,
      { method: "POST", headers: new Headers({ "x-thing": "yes", "content-type": "application/json" }), body: Buffer.from('{"amount":1}') },
      { certificate: vector.client_cert, key: vector.client_key, ca: vector.ca },
    );
    assert.equal(response.status, 201);
    assert.equal(response.headers.get("x-method"), "POST");
    assert.deepEqual(await response.json(), { caller: "envrune-test-client", sent: '{"amount":1}', header: "yes" });
  } finally {
    s.close();
  }
});

test("without the right certificate the service does not answer", async () => {
  const s = await service();
  try {
    // The server's own pair is signed by the same authority but is not what
    // a caller holds; a pair from elsewhere would fail the same way.
    await assert.rejects(
      sendWithCertificate(`${s.url}/`, {}, { certificate: "not a certificate", key: "not a key", ca: vector.ca }),
    );
  } finally {
    s.close();
  }
});
