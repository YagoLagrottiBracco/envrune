import "server-only";
import { createServerClient } from "@supabase/ssr";
import { createClient as createPlainClient, type SupabaseClient } from "@supabase/supabase-js";
import { cookies } from "next/headers";
import { publishableKey, secretKey, supabaseUrl } from "../env";

/** The signed-in user's client for server components and actions (cookies). */
export async function sessionClient(): Promise<SupabaseClient> {
  const store = await cookies();
  return createServerClient(supabaseUrl(), publishableKey(), {
    cookies: {
      getAll: () => store.getAll(),
      setAll(toSet) {
        try {
          for (const { name, value, options } of toSet) {
            store.set(name, value, options);
          }
        } catch {
          // Called from a server component, which cannot set cookies; the
          // proxy refreshes the session instead.
        }
      },
    },
  });
}

/**
 * A client that acts as the user whose access token the CLI sent, so that
 * row-level security applies to every query.
 */
export function bearerClient(accessToken: string): SupabaseClient {
  return createPlainClient(supabaseUrl(), publishableKey(), {
    global: { headers: { Authorization: `Bearer ${accessToken}` } },
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

/** A client that is nobody: for what anyone may ask, such as the schema's version. */
export function anonymousClient(): SupabaseClient {
  return createPlainClient(supabaseUrl(), publishableKey(), {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}

/** The service client. Only for machine tokens and the CLI sign-in. */
export function adminClient(): SupabaseClient {
  return createPlainClient(supabaseUrl(), secretKey(), {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
}
