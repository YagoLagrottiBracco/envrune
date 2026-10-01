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

export const supabaseUrl = () => required("NEXT_PUBLIC_SUPABASE_URL");
export const publishableKey = () => required("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY");
export const secretKey = () => required("SUPABASE_SECRET_KEY");
