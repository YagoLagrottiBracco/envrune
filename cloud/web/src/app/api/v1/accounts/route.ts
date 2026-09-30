import { ApiError, authenticated, handle, requireString, rpc } from "@/lib/api";

// GET ?email=: the user id and public account key of an account, for an
// admin about to add them. The CLI shows the key's fingerprint for the
// admin to compare with the new member before signing.
export const GET = handle(async (request) => {
  const { client } = await authenticated(request);
  const email = requireString(new URL(request.url).searchParams.get("email"), "email", 320);
  const found = await rpc<{ user_id: string; account_key: string }[]>(client, "lookup_account", { p_email: email });
  if (found.length === 0) {
    throw new ApiError(404, `${email} has no EnvRune account yet; ask them to run \`envrune cloud init\``);
  }
  return Response.json(found[0]);
});
