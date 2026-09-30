import { redirect } from "next/navigation";
import { sessionClient } from "@/lib/supabase/server";
import { AuthorizeButton } from "./authorize-button";

// `envrune login` opens this page with the port of a server it listens on,
// on this computer only, and a random state. After the user confirms, the
// new session goes to that server in a form POST, never in a URL.

export default async function AuthorizePage({ searchParams }: PageProps<"/cli/authorize">) {
  const params = await searchParams;
  const port = Number(params.port);
  const state = typeof params.state === "string" ? params.state : "";
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || !/^[A-Za-z0-9_-]{16,128}$/.test(state)) {
    return (
      <main className="mx-auto mt-24 max-w-md px-4">
        <h1 className="text-xl font-semibold">This link is not valid</h1>
        <p className="mt-4">Run <code>envrune login</code> again.</p>
      </main>
    );
  }
  const { data } = await (await sessionClient()).auth.getClaims();
  if (!data?.claims) {
    redirect(`/login?next=${encodeURIComponent(`/cli/authorize?port=${port}&state=${state}`)}`);
  }
  return (
    <main className="mx-auto mt-24 max-w-md px-4">
      <h1 className="text-2xl font-semibold">Sign in the EnvRune CLI?</h1>
      <p className="mt-4">
        The <code>envrune</code> command on this computer asked to sign in as <strong>{String(data.claims.email)}</strong>. Continue only if you just ran{" "}
        <code>envrune login</code>.
      </p>
      <AuthorizeButton port={port} state={state} />
    </main>
  );
}
