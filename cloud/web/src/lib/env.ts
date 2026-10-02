// Configuration from the environment. The publishable key is meant to be
// public; the secret key is used only on the server, for machine tokens and
// the CLI sign-in, and must never reach the browser.
//
// Values are read when a request needs them, by name, so the build does not
// inline them: one build, or one Docker image, serves any deployment. The
// browser gets the public two as props from the server (see app/login).

function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

/** The variables every deployment sets, in the order the guides list them. */
export const variables = ["NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", "SUPABASE_SECRET_KEY"] as const;

/** The variables that are not set yet. A server missing any shows how to set it up instead of failing. */
export const missing = () => variables.filter((name) => !process.env[name]);

export const supabaseUrl = () => required("NEXT_PUBLIC_SUPABASE_URL");
export const publishableKey = () => required("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY");
export const secretKey = () => required("SUPABASE_SECRET_KEY");
