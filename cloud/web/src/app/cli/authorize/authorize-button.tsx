"use client";

import { useRef, useState } from "react";
import { authorizeCli, type CliSession } from "./actions";

export function AuthorizeButton({ port, state }: { port: number; state: string }) {
  const [status, setStatus] = useState<"idle" | "working" | "done" | "error">("idle");
  const [message, setMessage] = useState("");
  const [session, setSession] = useState<CliSession | null>(null);
  const form = useRef<HTMLFormElement>(null);

  async function authorize() {
    setStatus("working");
    const result = await authorizeCli();
    if ("error" in result) {
      setStatus("error");
      setMessage(result.error);
      return;
    }
    setSession(result);
    setStatus("done");
    // Render the hidden fields, then post them to the CLI on this computer.
    setTimeout(() => form.current?.submit(), 0);
  }

  return (
    <div className="mt-6">
      <button onClick={authorize} disabled={status !== "idle"} className="rounded bg-neutral-900 px-4 py-2 text-white disabled:opacity-50 dark:bg-white dark:text-black">
        {status === "working" ? "Signing in…" : "Sign in the CLI"}
      </button>
      {status === "error" && <p className="mt-3 text-sm text-red-600">{message}</p>}
      {session && (
        <form ref={form} method="post" action={`http://127.0.0.1:${port}/callback`}>
          <input type="hidden" name="state" value={state} />
          <input type="hidden" name="access_token" value={session.access_token} />
          <input type="hidden" name="refresh_token" value={session.refresh_token} />
          <input type="hidden" name="expires_at" value={session.expires_at} />
        </form>
      )}
    </div>
  );
}
