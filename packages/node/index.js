// Loads the variables of the nearest envrune.yml from the EnvRune vault into
// process.env, as dotenv does from a .env file. The values come from the
// `envrune` CLI, which must be able to unlock the vault without a prompt:
// run `envrune unlock` first. It never falls back to a .env file.
import { execFileSync } from "node:child_process";

export class EnvruneError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "EnvruneError";
  }
}

/**
 * Loads variables into process.env and returns them.
 *
 * @param {object} [options]
 * @param {string} [options.env] environment to load; the default one otherwise
 * @param {string} [options.cwd] folder to look for envrune.yml from
 * @param {boolean} [options.override] replace variables that are already set
 * @param {string} [options.binary] the envrune executable; ENVRUNE_BIN or "envrune" otherwise
 * @returns {Record<string, string>}
 */
export function load(options = {}) {
  const binary = options.binary ?? process.env.ENVRUNE_BIN ?? "envrune";
  const args = ["env", "--format", "json", "--no-prompt"];
  if (options.env) {
    args.push("--env", options.env);
  }
  let output;
  try {
    output = execFileSync(binary, args, {
      cwd: options.cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" },
      windowsHide: true,
    });
  } catch (error) {
    if (error.code === "ENOENT") {
      throw new EnvruneError(
        `envrune was not found (${binary}). Install EnvRune and make sure it is on PATH, or set ENVRUNE_BIN.`,
        { cause: error },
      );
    }
    const detail = String(error.stderr ?? "").replace(/^\[ERROR\]\s*/gm, "").trim();
    throw new EnvruneError(
      detail || `envrune exited with code ${error.status}. Run \`envrune env\` in a terminal to see why.`,
      { cause: error },
    );
  }
  let values;
  try {
    values = JSON.parse(output);
  } catch (error) {
    throw new EnvruneError("envrune printed something that is not JSON. Update EnvRune.", { cause: error });
  }
  for (const [name, value] of Object.entries(values)) {
    if (options.override || process.env[name] === undefined) {
      process.env[name] = value;
    }
  }
  return values;
}

/** dotenv-style alias of load. */
export const config = load;
