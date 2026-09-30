import Link from "next/link";
import { sessionClient } from "@/lib/supabase/server";

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
    </main>
  );
}
