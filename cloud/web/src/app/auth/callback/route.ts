import { NextResponse } from "next/server";
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
      return NextResponse.redirect(new URL(next, url.origin));
    }
  }
  return NextResponse.redirect(new URL("/login?error=link", url.origin));
}

/** Only paths on this site, so the link cannot send the user elsewhere. */
function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}
