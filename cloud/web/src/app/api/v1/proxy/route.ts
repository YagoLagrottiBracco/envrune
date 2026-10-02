import { ApiError, handle } from "@/lib/api";
import { proxyIdentity } from "@/lib/env";
import { recipientOf } from "@/lib/sensitive";

// GET: the public half of this server's proxy identity, which sensitive
// secrets are sealed to. The CLI shows its fingerprint before an owner seals
// a value to it, and pins it. Public by nature; needs no session.
export const GET = handle(async () => {
  const identity = proxyIdentity();
  if (!identity) {
    throw new ApiError(404, "this server has no proxy identity, so it does not take sensitive secrets");
  }
  return Response.json({ recipient: await recipientOf(identity) });
});
