import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { sessionClient } from "@/lib/supabase/server";

// Metadata only: names, versions, roles, devices, rotation, and the audit
// log. The panel never decrypts values, and adding a member or approving a
// device happens in the CLI, which signs and wraps keys.

/* eslint-disable @typescript-eslint/no-explicit-any */

export default async function OrgPage({ params }: PageProps<"/orgs/[slug]">) {
  const { slug } = await params;
  const supabase = await sessionClient();
  const { data: claims } = await supabase.auth.getClaims();
  if (!claims?.claims) {
    redirect(`/login?next=/orgs/${slug}`);
  }
  const { data: org } = await supabase.from("organizations").select("id, slug, name").eq("slug", slug).maybeSingle();
  if (!org) {
    notFound();
  }
  const [members, projects, tasks, audit, tokens] = await Promise.all([
    supabase.from("org_members").select("user_id, role, scope").eq("org_id", org.id).order("role"),
    supabase.from("projects").select("slug, name, environments(id, slug, epoch, needs_rotation, secrets(name, current_version))").eq("org_id", org.id).order("slug"),
    supabase.from("rotation_tasks").select("id, reason, created_at, rotation_items(status, secrets(name, environments(slug, projects(slug))))").eq("org_id", org.id).order("created_at", { ascending: false }),
    supabase.from("audit_log").select("id, at, actor_user_id, actor_token_id, action, target").eq("org_id", org.id).order("id", { ascending: false }).limit(50),
    supabase.from("machine_tokens").select("id, name, scope, expires_at, revoked_at, last_used_at").eq("org_id", org.id),
  ]);
  const me = members.data?.find((m) => m.user_id === claims.claims.sub);
  const openTasks = (tasks.data ?? []).filter((t: any) => t.rotation_items.some((i: any) => i.status === "pending"));

  return (
    <main className="mx-auto my-12 max-w-4xl px-4">
      <p className="text-sm">
        <Link href="/" className="underline">
          Organizations
        </Link>
      </p>
      <h1 className="mt-2 text-2xl font-semibold">{org.name}</h1>
      <p className="text-sm text-neutral-500">Your role: {me?.role ?? "none"}</p>

      {openTasks.length > 0 && (
        <section className="mt-8 rounded border border-amber-500 p-4">
          <h2 className="font-semibold">Rotation needed</h2>
          {openTasks.map((t: any) => {
            const pending = t.rotation_items.filter((i: any) => i.status === "pending");
            return (
              <div key={t.id} className="mt-3">
                <p>
                  {t.reason} on {new Date(t.created_at).toLocaleDateString()}: they could read these {t.rotation_items.length} secrets; {pending.length} still to rotate.
                </p>
                <ul className="mt-2 list-disc pl-6 text-sm">
                  {pending.map((i: any) => (
                    <li key={`${i.secrets.environments.projects.slug}/${i.secrets.environments.slug}/${i.secrets.name}`}>
                      <code>
                        {i.secrets.environments.projects.slug}/{i.secrets.environments.slug}/{i.secrets.name}
                      </code>
                    </li>
                  ))}
                </ul>
                <p className="mt-2 text-sm">
                  Rotate each with <code>envrune cloud rotate &lt;project&gt;/&lt;environment&gt;/&lt;name&gt;</code>, or at the provider and then{" "}
                  <code>envrune cloud set</code>. Each new version marks its item done.
                </p>
              </div>
            );
          })}
        </section>
      )}

      <section className="mt-8">
        <h2 className="text-lg font-semibold">Projects</h2>
        {(projects.data ?? []).map((p: any) => (
          <div key={p.slug} className="mt-4">
            <h3 className="font-medium">{p.name}</h3>
            {p.environments.map((e: any) => (
              <div key={e.id} className="mt-2 pl-4">
                <p className="text-sm">
                  <code>{p.slug}/{e.slug}</code> · epoch {e.epoch}
                  {e.needs_rotation && <span className="ml-2 text-amber-600">needs a new epoch</span>}
                </p>
                <ul className="mt-1 pl-4 text-sm text-neutral-600 dark:text-neutral-400">
                  {e.secrets.map((s: any) => (
                    <li key={s.name}>
                      {s.name} · v{s.current_version}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        ))}
      </section>

      <section className="mt-8">
        <h2 className="text-lg font-semibold">Members</h2>
        <table className="mt-2 w-full text-sm">
          <tbody>
            {(members.data ?? []).map((m) => (
              <tr key={m.user_id} className="border-b border-neutral-200 dark:border-neutral-800">
                <td className="py-1 font-mono text-xs">{m.user_id}</td>
                <td>{m.role}</td>
                <td>{m.scope.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-2 text-sm text-neutral-500">
          Add or remove members with <code>envrune cloud member add|remove</code>: the CLI signs the change and shares keys, which this site cannot do.
        </p>
      </section>

      {tokens.data && tokens.data.length > 0 && (
        <section className="mt-8">
          <h2 className="text-lg font-semibold">Machine tokens</h2>
          <ul className="mt-2 text-sm">
            {tokens.data.map((t) => (
              <li key={t.id}>
                <code>{t.name || t.id}</code> · {t.scope.join(", ")} · {t.revoked_at ? "revoked" : `expires ${new Date(t.expires_at).toLocaleDateString()}`}
                {t.last_used_at && ` · last used ${new Date(t.last_used_at).toLocaleString()}`}
              </li>
            ))}
          </ul>
        </section>
      )}

      {audit.data && audit.data.length > 0 && (
        <section className="mt-8">
          <h2 className="text-lg font-semibold">Recent activity</h2>
          <table className="mt-2 w-full text-sm">
            <tbody>
              {audit.data.map((a) => (
                <tr key={a.id} className="border-b border-neutral-200 dark:border-neutral-800">
                  <td className="py-1 pr-4 whitespace-nowrap">{new Date(a.at).toLocaleString()}</td>
                  <td className="pr-4">{a.action}</td>
                  <td className="pr-4 font-mono text-xs">{a.target}</td>
                  <td className="font-mono text-xs">{a.actor_token_id ? `token ${a.actor_token_id}` : a.actor_user_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="mt-2 text-sm text-neutral-500">
            Export and verify the whole log with <code>envrune cloud audit export</code>.
          </p>
        </section>
      )}
    </main>
  );
}
