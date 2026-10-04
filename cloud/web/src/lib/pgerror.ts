// What a database error becomes in an answer to the CLI.

/** The errcodes the schema raises, as HTTP statuses. */
const statuses: Record<string, number> = {
  "28000": 401, // sign in first
  "42501": 403, // not allowed
  P0002: 404, // not found
  "23505": 409, // already exists
  "40001": 409, // stale version or epoch: sync and retry
  "22023": 400, // invalid value
  "23514": 400, // check constraint
  "22P02": 400, // invalid input syntax
};

/** A table or function this server expects is not in the database. */
const schemaMissing = new Set(["PGRST202", "PGRST205", "42P01", "42883"]);

export const schemaMissingMessage =
  "this EnvRune Cloud server's database is missing tables or functions; whoever runs it applies every file in cloud/supabase/migrations";

/**
 * The status and message for a database error. The schema's own errors
 * carry a message written for the caller. Any other is the server's
 * problem: the caller gets its code, which says nothing about the data, and
 * the server's log gets the rest.
 */
export function answerFor(code: string | undefined, message: string): { status: number; message: string } {
  if (code && statuses[code]) {
    return { status: statuses[code], message };
  }
  if (code && schemaMissing.has(code)) {
    return { status: 503, message: schemaMissingMessage };
  }
  return { status: 500, message: code && /^[A-Z0-9]{5,8}$/.test(code) ? `the request failed (database error ${code})` : "the request failed" };
}
