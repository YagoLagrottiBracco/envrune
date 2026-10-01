"use client";

import { useState } from "react";
import { useSearchParams } from "next/navigation";
import { createBrowserClient } from "@supabase/ssr";

export function LoginForm({ supabaseUrl, publishableKey }: { supabaseUrl: string; publishableKey: string }) {
  const params = useSearchParams();
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "sent" | "error">(params.get("error") ? "error" : "idle");
  const [message, setMessage] = useState(params.get("error") ? "That sign-in link expired or was already used. Ask for a new one." : "");

  async function send(event: React.FormEvent) {
    event.preventDefault();
    setState("sending");
    const next = params.get("next") ?? "/";
    const { error } = await createBrowserClient(supabaseUrl, publishableKey).auth.signInWithOtp({
      email,
      options: { emailRedirectTo: `${window.location.origin}/auth/callback?next=${encodeURIComponent(next)}` },
    });
    if (error) {
      setState("error");
      setMessage(error.message);
    } else {
      setState("sent");
    }
  }

  return (
    <main className="mx-auto mt-24 max-w-sm px-4">
      <h1 className="text-2xl font-semibold">Sign in to EnvRune Cloud</h1>
      {state === "sent" ? (
        <p className="mt-6">Check {email} for a sign-in link. You can close this tab after you open it.</p>
      ) : (
        <form onSubmit={send} className="mt-6 flex flex-col gap-3">
          <label htmlFor="email" className="text-sm">
            Email
          </label>
          <input
            id="email"
            type="email"
            required
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="rounded border border-neutral-400 px-3 py-2 dark:bg-neutral-900"
          />
          <button type="submit" disabled={state === "sending"} className="rounded bg-neutral-900 px-3 py-2 text-white disabled:opacity-50 dark:bg-white dark:text-black">
            {state === "sending" ? "Sending…" : "Email me a sign-in link"}
          </button>
          {state === "error" && <p className="text-sm text-red-600">{message}</p>}
        </form>
      )}
    </main>
  );
}
