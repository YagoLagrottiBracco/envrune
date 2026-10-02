import { connection } from "next/server";
import { missing } from "@/lib/env";

// Where every page leads until the server has the address and keys of its
// Supabase. It names the variables, never a value.
export default async function NotConfigured() {
  await connection();
  const names = missing();
  return (
    <main className="mx-auto mt-24 max-w-xl px-4">
      <h1 className="text-3xl font-semibold">EnvRune Cloud</h1>
      <p className="mt-4">
        This server is running, but it is not connected to its database yet. Whoever runs it needs to set{" "}
        {names.length === 1 ? "this environment variable" : "these environment variables"} and start it again:
      </p>
      <ul className="mt-4 list-disc pl-6 font-mono text-sm">
        {names.map((name) => (
          <li key={name}>{name}</li>
        ))}
      </ul>
      <p className="mt-4 text-sm text-neutral-500">
        The setup is described in{" "}
        <a href="https://github.com/YagoLagrottiBracco/envrune/blob/main/docs/self-hosting.md" className="underline">
          the self-hosting guide
        </a>
        .
      </p>
    </main>
  );
}
