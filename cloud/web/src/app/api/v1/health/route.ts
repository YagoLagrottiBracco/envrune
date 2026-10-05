import { notConfigured } from "@/lib/api";
import { missing } from "@/lib/env";
import { databaseState, type DatabaseState } from "@/lib/schema";
import { anonymousClient } from "@/lib/supabase/server";

// GET: whether this is an EnvRune Cloud server, which API it speaks, and
// whether its database has the schema this version needs. Before the server
// is configured it says so, so `envrune login` and health checks do not
// take it for a working one. A database that is behind does not make the
// server unhealthy: it answers, and says what is wrong.
export async function GET() {
  if (missing().length > 0) {
    return notConfigured();
  }
  return Response.json({ service: "envrune-cloud", api: 1, database: await database() });
}

async function database(): Promise<DatabaseState> {
  try {
    const { data, error } = await anonymousClient().rpc("schema_version");
    if (error) {
      // PGRST202: the function is not there, so the schema predates it.
      return databaseState(error.code === "PGRST202" || error.code === "42883" ? { missing: true } : null);
    }
    return databaseState({ version: data });
  } catch {
    return "unreachable";
  }
}
