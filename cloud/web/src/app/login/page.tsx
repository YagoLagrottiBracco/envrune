import { Suspense } from "react";
import { connection } from "next/server";
import { publishableKey, supabaseUrl } from "@/lib/env";
import { LoginForm } from "./login-form";

// Rendered per request, so the browser gets the address and public key of
// the Supabase this server was started with, not the ones of the build.
export default async function LoginPage() {
  await connection();
  return (
    <Suspense>
      <LoginForm supabaseUrl={supabaseUrl()} publishableKey={publishableKey()} />
    </Suspense>
  );
}
