import { sessionClient } from "@/lib/supabase/server";

// The sign-in link lands here: exchange its code for a session cookie, then
// go where the user was going.
export async function GET(request: Request) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const next = safeNext(url.searchParams.get("next"));
  if (code) {
    const supabase = await sessionClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) {
      return to(next);
    }
  }
  return to("/login?error=link");
}

/**
 * A redirect to a path on this site. The Location is the path alone: in the
 * Docker image, or behind a reverse proxy, this server does not know the
 * address browsers reach it at, and the request's own URL says localhost.
 */
function to(path: string): Response {
  return new Response(null, { status: 307, headers: { Location: path } });
}

/** Only paths on this site, so the link cannot send the user elsewhere. */
function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}
