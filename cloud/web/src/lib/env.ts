// Configuration from the environment. The publishable key is meant to be
// public; the secret key is used only on the server, for machine tokens and
// the CLI sign-in, and must never reach the browser.

function required(name: string, value: string | undefined): string {
  if (!value) {
    throw new Error(`${name} is not set`);
  }
  return value;
}

export const supabaseUrl = () => required("NEXT_PUBLIC_SUPABASE_URL", process.env.NEXT_PUBLIC_SUPABASE_URL);
export const publishableKey = () => required("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY);
export const secretKey = () => required("SUPABASE_SECRET_KEY", process.env.SUPABASE_SECRET_KEY);
