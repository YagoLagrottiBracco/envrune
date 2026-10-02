import { ApiError, authenticated, fromPostgres, handle } from "@/lib/api";

// GET ?env=<id>&env=<id>: the epoch and the version number of each secret of
// the environments named, for a device to learn whether its copy is behind.
// Names and numbers only, which every member may read: no ciphertext leaves
// the server, so this is not a fetch and is not in the audit log.
export const GET = handle(async (request) => {
  const { client } = await authenticated(request);
  const ids = new URL(request.url).searchParams.getAll("env");
  if (ids.length === 0 || ids.length > 50) {
    throw new ApiError(400, "name 1 to 50 environments with env=<id>");
  }
  const { data, error } = await client.from("environments").select("id, epoch, secrets(name, current_version)").in("id", ids);
  if (error) {
    throw fromPostgres(error);
  }
  const out: Record<string, { epoch: number; secrets: Record<string, number> }> = {};
  for (const e of data) {
    out[e.id] = { epoch: e.epoch, secrets: Object.fromEntries(e.secrets.map((s) => [s.name, s.current_version])) };
  }
  return Response.json(out);
});
