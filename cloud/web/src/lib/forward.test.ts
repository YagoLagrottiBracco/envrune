import { test } from "node:test";
import assert from "node:assert/strict";
import { buildResponse, buildUpstream, ForwardRefused, type Substitution } from "./forward.ts";

const placeholder = "envrune_sealed_0123456789abcdef0123456789abcdef";
const secret: Substitution = { placeholder, value: Buffer.from("the-real-value"), hosts: ["api.example.com"] };

function headersOf(init: RequestInit): Record<string, string> {
  return Object.fromEntries((init.headers as Headers).entries());
}

test("the value replaces the placeholder in headers, basic credentials, the address, and text bodies", () => {
  const basic = "Basic " + Buffer.from(`${placeholder}:`).toString("base64");
  const { url, init } = buildUpstream(
    {
      method: "post",
      target: `https://api.example.com/v1/charges/${placeholder}?key=${placeholder}&n=1`,
      headers: [
        ["Authorization", `Bearer ${placeholder}`],
        ["X-Other", basic],
        ["Content-Type", "application/json"],
        ["Host", "elsewhere.example.net"],
        ["Accept-Encoding", "gzip"],
        ["X-EnvRune-Device", "d1"],
      ],
      body: Buffer.from(JSON.stringify({ token: placeholder, amount: 10 })),
    },
    [secret],
  );
  assert.equal(url, "https://api.example.com/v1/charges/the-real-value?key=the-real-value&n=1");
  const headers = headersOf(init);
  assert.equal(headers.authorization, "Bearer the-real-value");
  assert.equal(headers["x-other"], basic, "only the Authorization header is read as basic credentials");
  assert.equal(headers.host, undefined);
  assert.equal(headers["x-envrune-device"], undefined);
  assert.equal(headers["accept-encoding"], "identity");
  assert.equal(init.method, "POST");
  assert.equal(init.redirect, "manual");
  assert.deepEqual(JSON.parse(Buffer.from(init.body as Uint8Array).toString()), { token: "the-real-value", amount: 10 });

  const withBasic = buildUpstream(
    { method: "GET", target: "https://api.example.com/", headers: [["authorization", basic]], body: null },
    [secret],
  );
  assert.equal(headersOf(withBasic.init).authorization, "Basic " + Buffer.from("the-real-value:").toString("base64"));
  assert.equal(withBasic.init.body, undefined);
});

test("a body that is not text is forwarded untouched", () => {
  const body = Buffer.from(`\x00\x01${placeholder}`);
  const { init } = buildUpstream(
    { method: "PUT", target: "https://api.example.com/upload", headers: [["content-type", "application/octet-stream"]], body },
    [secret],
  );
  assert.deepEqual(Buffer.from(init.body as Uint8Array), body);
});

test("a secret goes only to the hosts its owner allowed, over https", () => {
  const refused = (target: string, status: number) =>
    assert.throws(
      () => buildUpstream({ method: "GET", target, headers: [], body: null }, [secret]),
      (e) => e instanceof ForwardRefused && e.status === status,
      target,
    );
  refused("https://evil.example.net/collect", 403);
  refused("https://api.example.com.evil.example.net/", 403);
  refused("http://api.example.com/", 400);
  refused("https://api.example.com:8443/", 400);
  refused("https://user:pass@api.example.com/", 400);
  refused("not an address", 400);
  // Two secrets in one request: the host must be allowed by both.
  const other: Substitution = { placeholder: "envrune_sealed_ffffffffffffffffffffffffffffffff", value: Buffer.from("v2"), hosts: ["b.example.org"] };
  assert.throws(() => buildUpstream({ method: "GET", target: "https://api.example.com/", headers: [], body: null }, [secret, other]), ForwardRefused);
});

test("only placeholders made by envrune are replaced", () => {
  const forged: Substitution = { placeholder: "a", value: Buffer.from("x"), hosts: ["api.example.com"] };
  assert.throws(() => buildUpstream({ method: "GET", target: "https://api.example.com/", headers: [], body: null }, [forged]), ForwardRefused);
});

test("a value that would change where the request goes is refused", () => {
  const sneaky: Substitution = { placeholder, value: Buffer.from("@evil.example.net/"), hosts: ["api.example.com"] };
  const result = () => buildUpstream({ method: "GET", target: `https://api.example.com/${placeholder}`, headers: [], body: null }, [sneaky]);
  // In the path it stays a path; the host is unchanged.
  assert.equal(new URL(result().url).host, "api.example.com");
});

test("a value echoed by the service comes back as the placeholder", async () => {
  const upstream = new Response(JSON.stringify({ key: "the-real-value", ok: true }), {
    status: 201,
    headers: { "content-type": "application/json; charset=utf-8", "x-echo": "Bearer the-real-value", "transfer-encoding": "chunked" },
  });
  const response = await buildResponse(upstream, [secret]);
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("x-echo"), `Bearer ${placeholder}`);
  assert.equal(response.headers.get("transfer-encoding"), null);
  assert.equal(response.headers.get("x-envrune-forward"), "upstream");
  assert.deepEqual(await response.json(), { key: placeholder, ok: true });

  const binary = Buffer.from("\x00the-real-value");
  const untouched = await buildResponse(new Response(binary, { headers: { "content-type": "application/octet-stream" } }), [secret]);
  assert.deepEqual(Buffer.from(await untouched.arrayBuffer()), binary);
});
