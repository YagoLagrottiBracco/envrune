"use strict";

// Finds the environment variables that source code reads, so the extension
// can warn about the ones envrune.yml does not link. It reads names only.

const NAME = "[A-Z_][A-Z0-9_]*";

/** Patterns per language; each captures the variable name as group 1. */
const PATTERNS = {
  javascript: [
    new RegExp(`\\bprocess\\.env\\.(${NAME})\\b`, "g"),
    new RegExp(`\\bprocess\\.env\\[\\s*["'\`](${NAME})["'\`]\\s*\\]`, "g"),
    new RegExp(`\\bimport\\.meta\\.env\\.(${NAME})\\b`, "g"),
    new RegExp(`\\bDeno\\.env\\.get\\(\\s*["'\`](${NAME})["'\`]`, "g"),
    new RegExp(`\\bBun\\.env\\.(${NAME})\\b`, "g"),
  ],
  python: [
    new RegExp(`\\bos\\.environ\\[\\s*["'](${NAME})["']\\s*\\]`, "g"),
    new RegExp(`\\bos\\.environ\\.get\\(\\s*["'](${NAME})["']`, "g"),
    new RegExp(`\\bos\\.getenv\\(\\s*["'](${NAME})["']`, "g"),
  ],
};

const LANGUAGES = {
  javascript: "javascript",
  javascriptreact: "javascript",
  typescript: "javascript",
  typescriptreact: "javascript",
  vue: "javascript",
  svelte: "javascript",
  astro: "javascript",
  python: "python",
};

/** Variables that the system or the tooling sets, not the project. */
const IGNORED = new Set([
  "NODE_ENV", "PATH", "HOME", "USER", "USERNAME", "PWD", "SHELL", "TERM", "LANG", "TZ",
  "CI", "TMPDIR", "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOSTNAME",
  "DEBUG", "MODE", "DEV", "PROD", "SSR", "BASE_URL", "VERCEL", "VERCEL_ENV", "VERCEL_URL",
  "GITHUB_ACTIONS", "NODE_OPTIONS", "PYTHONPATH", "VIRTUAL_ENV",
]);

/**
 * Returns every environment variable the text reads.
 * @param {string} text
 * @param {string} languageId a VS Code language id
 * @returns {{name: string, index: number, length: number}[]} index and
 *   length locate the name itself in text
 */
function findEnvReferences(text, languageId) {
  const family = LANGUAGES[languageId];
  if (!family) {
    return [];
  }
  const found = [];
  for (const pattern of PATTERNS[family]) {
    pattern.lastIndex = 0;
    for (let match; (match = pattern.exec(text)) !== null; ) {
      const name = match[1];
      // The name is the last thing each pattern captures, before closing
      // quotes or brackets.
      found.push({ name, index: match.index + match[0].lastIndexOf(name), length: name.length });
    }
  }
  found.sort((a, b) => a.index - b.index);
  return found;
}

/**
 * Returns the references that no environment of envrune.yml links.
 * @param {{name: string}[]} references from findEnvReferences
 * @param {Set<string>} linked variable names linked in any environment
 * @param {string[]} [ignore] more names to leave alone
 */
function unlinked(references, linked, ignore = []) {
  const skip = new Set([...IGNORED, ...ignore]);
  return references.filter((r) => !linked.has(r.name) && !skip.has(r.name) && !r.name.startsWith("NEXT_RUNTIME"));
}

/**
 * Proposes a vault reference for a variable, as `envrune setup` does:
 * project.variable.environment.
 */
function suggestReference(project, variable, environment) {
  const slug = (text) => {
    let out = String(text).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    if (!/^[a-z]/.test(out)) {
      out = "v" + out;
    }
    return out;
  };
  return [project, variable, environment].map(slug).join(".");
}

module.exports = { findEnvReferences, unlinked, suggestReference, IGNORED };
