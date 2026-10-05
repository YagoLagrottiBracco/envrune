// The database schema this version of the server needs: the newest
// migration in cloud/supabase/migrations, which is what the database's
// schema_version() answers once it is applied. schema.test.ts fails when a
// migration is added without moving this.

export const expectedSchema = 20261005140000;

export type DatabaseState = "ok" | "behind" | "ahead" | "unreachable";

/**
 * What a database's answer to schema_version() means. A database from
 * before that function existed does not have it, and is behind.
 */
export function databaseState(answer: { version?: unknown; missing?: boolean } | null): DatabaseState {
  if (answer === null) {
    return "unreachable";
  }
  if (answer.missing) {
    return "behind";
  }
  const version = Number(answer.version);
  if (!Number.isSafeInteger(version)) {
    return "unreachable";
  }
  return version === expectedSchema ? "ok" : version < expectedSchema ? "behind" : "ahead";
}
