import Link from "next/link";
import { sessionClient } from "@/lib/supabase/server";
import { revokeDevice } from "./actions";

export default async function Home() {
  const supabase = await sessionClient();
  const { data } = await supabase.auth.getClaims();
  if (!data?.claims) {
    return (
      <main className="mx-auto mt-24 max-w-xl px-4">
        <h1 className="text-3xl font-semibold">EnvRune Cloud</h1>
        <p className="mt-4">
          Share secrets with your team without the server ever seeing them. Values are encrypted on your machine by the <code>envrune</code> CLI; this site
          manages who can use them and shows who did what.
        </p>
        <p className="mt-6 flex gap-4">
          <Link href="/login" className="rounded bg-neutral-900 px-4 py-2 text-white dark:bg-white dark:text-black">
            Sign in
          </Link>
          <a href="https://github.com/YagoLagrottiBracco/envrune/blob/main/docs/cloud.md" className="px-4 py-2 underline">
            How it works
          </a>
        </p>
      </main>
    );
  }
  const { data: memberships } = await supabase
    .from("org_members")
    .select("role, organizations(slug, name)")
    .eq("user_id", data.claims.sub)
    .neq("role", "removed");
  const { data: devices } = await supabase
    .from("devices")
    .select("id, name, signature, revoked_at, registered_at")
    .eq("user_id", data.claims.sub)
    .eq("kind", "device")
    .order("registered_at");
  return (
    <main className="mx-auto mt-16 max-w-3xl px-4">
      <h1 className="text-2xl font-semibold">Organizations</h1>
      {!memberships?.length ? (
        <p className="mt-4">
          You are not in an organization yet. Create one with <code>envrune cloud org create &lt;name&gt;</code>, or ask an admin to add you.
        </p>
      ) : (
        <ul className="mt-6 divide-y divide-neutral-300 dark:divide-neutral-700">
          {memberships.map((m) => {
            const org = m.organizations as unknown as { slug: string; name: string };
            return (
              <li key={org.slug} className="flex justify-between py-3">
                <Link href={`/orgs/${org.slug}`} className="font-medium underline">
                  {org.name}
                </Link>
                <span className="text-sm text-neutral-500">{m.role}</span>
              </li>
            );
          })}
        </ul>
      )}

      <h2 className="mt-12 text-lg font-semibold">Your devices</h2>
      <ul className="mt-4 divide-y divide-neutral-300 text-sm dark:divide-neutral-700">
        {(devices ?? []).map((d) => (
          <li key={d.id} className="flex items-center justify-between py-2">
            <span>
              {d.name || "unnamed"} <code className="text-xs text-neutral-500">{d.id}</code>
            </span>
            {d.revoked_at ? (
              <span className="text-neutral-500">revoked</span>
            ) : !d.signature ? (
              <span className="text-neutral-500">waiting for approval</span>
            ) : (
              <form action={revokeDevice.bind(null, d.id)}>
                <button type="submit" className="underline">
                  Revoke
                </button>
              </form>
            )}
          </li>
        ))}
      </ul>
      <p className="mt-2 text-sm text-neutral-500">
        Revoke a device you lost. It is cut off at once, and the secrets it fetched are listed under rotation in each organization. Then run{" "}
        <code>envrune cloud rotate</code> for the environments it used, from a device you still have: only a device can make new keys.
      </p>
    </main>
  );
}
