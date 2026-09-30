"use server";

import { createClient } from "@supabase/supabase-js";
import { publishableKey, supabaseUrl } from "@/lib/env";
import { adminClient, sessionClient } from "@/lib/supabase/server";

export interface CliSession {
  access_token: string;
  refresh_token: string;
  expires_at: number;
}

/**
 * Creates a session for the CLI, separate from the browser's: refresh
 * tokens are single-use, so sharing one would sign the other out. The
 * signed-in user asks for it; the server mints a one-time sign-in token for
 * their own email and redeems it at once, in a client that stores nothing,
 * so the browser keeps its own session.
 */
export async function authorizeCli(): Promise<CliSession | { error: string }> {
  const { data: claims } = await (await sessionClient()).auth.getClaims();
  const email = claims?.claims.email;
  if (!email) {
    return { error: "Sign in first." };
  }
  const link = await adminClient().auth.admin.generateLink({ type: "magiclink", email });
  const tokenHash = link.data?.properties?.hashed_token;
  if (link.error || !tokenHash) {
    return { error: "Could not create a session for the CLI." };
  }
  const detached = createClient(supabaseUrl(), publishableKey(), { auth: { persistSession: false, autoRefreshToken: false } });
  const { data, error } = await detached.auth.verifyOtp({ type: "email", token_hash: tokenHash });
  if (error || !data.session) {
    return { error: "Could not create a session for the CLI." };
  }
  const { access_token, refresh_token, expires_at } = data.session;
  return { access_token, refresh_token, expires_at: expires_at ?? 0 };
}
