import { notConfigured } from "@/lib/api";
import { missing } from "@/lib/env";

// GET: whether this is an EnvRune Cloud server, and which API it speaks.
// Before the server is configured it says so, so `envrune login` and health
// checks do not take it for a working one.
export function GET() {
  return missing().length > 0 ? notConfigured() : Response.json({ service: "envrune-cloud", api: 1 });
}
