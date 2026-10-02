import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import { allowedTarget, isPrivateAddress, send, sign } from "./webhook.ts";

test("the signature is the HMAC-SHA256 of the body", () => {
  const secret = Buffer.alloc(32, 7);
  assert.equal(sign(secret, '{"a":1}'), "sha256=" + createHmac("sha256", secret).update('{"a":1}').digest("hex"));
});

test("private and local addresses are told from public ones", () => {
  for (const a of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:10.0.0.1"]) {
    assert.equal(isPrivateAddress(a), true, a);
  }
  for (const a of ["8.8.8.8", "172.32.0.1", "1.1.1.1", "2606:4700:4700::1111"]) {
    assert.equal(isPrivateAddress(a), false, a);
  }
});

test("only https to a public address is sent to, unless private ones are allowed", async () => {
  assert.equal(await allowedTarget("http://example.com/hook", false), "the address must use https");
  assert.equal(await allowedTarget("https://127.0.0.1/hook", false), "the address is on a private network");
  assert.equal(await allowedTarget("https://[::1]/hook", false), "the address is on a private network");
  assert.equal(await allowedTarget("https://169.254.169.254/latest/meta-data", false), "the address is on a private network");
  assert.equal(await allowedTarget("not an address", false), "the address is not valid");
  assert.equal(await allowedTarget("http://127.0.0.1:9/hook", true), null);
  assert.equal(await allowedTarget("ftp://127.0.0.1/hook", true), "the address must use https");
});

test("an event is posted, signed, and a failure is reported", async () => {
  const received: { signature?: string; event?: string; body: string }[] = [];
  let status = 200;
  const server = http.createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => {
      received.push({ signature: request.headers["x-envrune-signature"] as string, event: request.headers["x-envrune-event"] as string, body });
      response.writeHead(status).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/hook`;
  const secret = Buffer.alloc(32, 9);
  const event = { id: 1, payload: { action: "member.removed", target: "bob" }, url, secret: secret.toString("base64") };
  try {
    assert.equal(await send(event, true), null);
    assert.equal(received[0].event, "member.removed");
    assert.equal(received[0].signature, sign(secret, received[0].body));
    assert.deepEqual(JSON.parse(received[0].body), event.payload);
    status = 500;
    assert.equal(await send(event, true), "the receiver answered 500");
    // Without leave to use private addresses, nothing is sent.
    assert.match((await send(event, false)) ?? "", /https|private/);
    assert.equal(received.length, 2);
  } finally {
    server.close();
  }
});
