export class EnvruneError extends Error {}

export interface LoadOptions {
  /** Environment to load; the default one of envrune.yml otherwise. */
  env?: string;
  /** Folder to look for envrune.yml from; the current one otherwise. */
  cwd?: string;
  /** Replace variables that are already set in process.env. */
  override?: boolean;
  /** The envrune executable; ENVRUNE_BIN or "envrune" otherwise. */
  binary?: string;
}

/** Loads variables from the EnvRune vault into process.env and returns them. */
export function load(options?: LoadOptions): Record<string, string>;

/** dotenv-style alias of load. */
export const config: typeof load;
