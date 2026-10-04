import "server-only";
import { after } from "next/server";
import { deliverWebhooks } from "./deliver";
import type { PostgrestError, SupabaseClient } from "@supabase/supabase-js";
import { missing } from "./env";
import { answerFor } from "./pgerror";
import { bearerClient } from "./supabase/server";

// Helpers for the /api/v1 route handlers the CLI calls.

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export function fromPostgres(error: PostgrestError): ApiError {
  const answer = answerFor(error.code, error.message);
  if (answer.status >= 500) {
    console.error(`database error ${error.code}: ${error.message}`);
  }
  return new ApiError(answer.status, answer.message);
}

/** Wraps a handler: turns ApiError and Postgres errors into JSON responses. */
export function handle<C>(fn: (request: Request, context: C) => Promise<Response>) {
  return async (request: Request, context: C): Promise<Response> => {
    if (missing().length > 0) {
      return notConfigured();
    }
    // What a request changed may be an event some organization is told
    // about: send what is waiting once the caller has their answer.
    if (request.method !== "GET" && request.method !== "HEAD") {
      after(() => deliverWebhooks().catch(() => 0));
    }
    try {
      return await fn(request, context);
    } catch (error) {
      if (error instanceof ApiError) {
        return Response.json({ error: error.message }, { status: error.status });
      }
      console.error(error);
      return Response.json({ error: "the request failed" }, { status: 500 });
    }
  };
}

/** What a server answers before its Supabase address and keys are set. */
export function notConfigured(): Response {
  return Response.json({ error: "this EnvRune Cloud server is not configured yet; ask whoever runs it" }, { status: 503 });
}

/**
 * The caller, from `Authorization: Bearer <access token>`: a client that
 * acts as them under row-level security, and their user id, checked with
 * the auth server.
 */
export async function authenticated(request: Request): Promise<{ client: SupabaseClient; userId: string }> {
  const header = request.headers.get("authorization") ?? "";
  const token = header.match(/^Bearer\s+(\S+)$/i)?.[1];
  if (!token) {
    throw new ApiError(401, "sign in with `envrune login`");
  }
  const client = bearerClient(token);
  const { data, error } = await client.auth.getUser(token);
  if (error || !data.user) {
    throw new ApiError(401, "the session expired; run `envrune login` again");
  }
  return { client, userId: data.user.id };
}

/** The organization id for a slug the caller is a member of. */
export async function orgBySlug(client: SupabaseClient, slug: string): Promise<{ id: string; slug: string; name: string; offline_days: number | null }> {
  const { data, error } = await client.from("organizations").select("id, slug, name, offline_days").eq("slug", slug).maybeSingle();
  if (error) {
    throw fromPostgres(error);
  }
  if (!data) {
    throw new ApiError(404, `no organization ${slug} that you are a member of`);
  }
  return data;
}

/** The caller's account key, base64. */
export async function accountKey(client: SupabaseClient, userId: string): Promise<string> {
  const { data, error } = await client.from("profiles").select("account_key").eq("user_id", userId).maybeSingle();
  if (error) {
    throw fromPostgres(error);
  }
  if (!data) {
    throw new ApiError(404, "register the account first with `envrune cloud init`");
  }
  return base64(data.account_key)!;
}

/** Calls a database function and throws ApiError on failure. */
export async function rpc<T = unknown>(client: SupabaseClient, fn: string, args: Record<string, unknown>): Promise<T> {
  const { data, error } = await client.rpc(fn, args);
  if (error) {
    throw fromPostgres(error);
  }
  return data as T;
}

export async function body<T>(request: Request): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    throw new ApiError(400, "the body is not JSON");
  }
}

export function requireString(value: unknown, name: string, max = 200): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new ApiError(400, `${name} is required`);
  }
  return value;
}

export function requireStrings(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw new ApiError(400, `${name} must be a list of strings`);
  }
  return value as string[];
}

export function requireInteger(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ApiError(400, `${name} must be a whole number`);
  }
  return value;
}

/** bytea arguments are sent to PostgREST as \x-prefixed hex. */
export function bytea(base64: unknown, name: string): string {
  if (typeof base64 !== "string") {
    throw new ApiError(400, `${name} must be base64`);
  }
  return "\\x" + Buffer.from(base64, "base64").toString("hex");
}

/** bytea values come back from PostgREST as \x-prefixed hex; the CLI wants base64. */
export function base64(hex: string | null): string | null {
  return hex === null ? null : Buffer.from(hex.replace(/^\\x/, ""), "hex").toString("base64");
}
