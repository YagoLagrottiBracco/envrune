"use strict";

// Runs the envrune CLI. The extension only asks it for names and states
// (status, inspect) and, for debugging, for the variables of an environment,
// which go straight into the debug session and nowhere else.

const { execFile } = require("node:child_process");

class EnvruneError extends Error {}

/**
 * Runs envrune with args in cwd and resolves with its standard output.
 * @param {string} binary
 * @param {string[]} args
 * @param {string} [cwd]
 * @returns {Promise<string>}
 */
function run(binary, args, cwd) {
  return new Promise((resolve, reject) => {
    execFile(
      binary,
      args,
      { cwd, env: { ...process.env, NO_COLOR: "1" }, windowsHide: true, maxBuffer: 16 << 20, timeout: 60_000 },
      (error, stdout, stderr) => {
        if (error) {
          if (error.code === "ENOENT") {
            reject(new EnvruneError(`EnvRune was not found (${binary}). Install it, or set envrune.path in the settings.`));
            return;
          }
          const detail = String(stderr).replace(/^\[ERROR\]\s*/gm, "").trim();
          reject(new EnvruneError(detail || `envrune ${args[0]} failed.`));
          return;
        }
        resolve(stdout);
      },
    );
  });
}

async function json(binary, args, cwd) {
  const out = await run(binary, args, cwd);
  try {
    return JSON.parse(out);
  } catch {
    throw new EnvruneError(`envrune ${args[0]} printed something that is not JSON. Update EnvRune.`);
  }
}

/** The unlock state; never unlocks. */
const status = (binary, cwd) => json(binary, ["status", "--format", "json"], cwd);

/** envrune.yml as names, references, and stored states; never values. */
const inspect = (binary, dir) => json(binary, ["inspect", "--dir", dir], dir);

/** The variables of an environment, for a debug session. Never prompts. */
function variables(binary, cwd, environment) {
  const args = ["env", "--format", "json", "--no-prompt"];
  if (environment) {
    args.push("--env", environment);
  }
  return json(binary, args, cwd);
}

module.exports = { EnvruneError, run, status, inspect, variables };
