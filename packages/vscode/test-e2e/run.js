"use strict";

// Runs the extension in a VS Code downloaded for the test, against a
// workspace with an envrune.yml and a real vault unlocked through
// ENVRUNE_PASSWORD. Usage: node test-e2e/run.js <path to envrune binary>
// (needs `npm install --no-save @vscode/test-electron`).

const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");
const { execFileSync } = require("node:child_process");
const { runTests } = require("@vscode/test-electron");

async function main() {
  // Set when this runs from a VS Code terminal or task; it would make the
  // test VS Code start as plain Node.
  delete process.env.ELECTRON_RUN_AS_NODE;
  const envrune = path.resolve(process.argv[2]);
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "envrune-vscode-"));
  const vault = path.join(workspace, ".vault", "vault.ev1");
  fs.writeFileSync(
    path.join(workspace, "envrune.yml"),
    "version: 1\nproject: demo\ndefault_env: development\ncommands:\n  hello: node -e \"1\"\nenvironments:\n  development:\n    API_KEY: demo.api-key\n",
  );
  fs.writeFileSync(path.join(workspace, "app.js"), "require('fs').writeFileSync(process.argv[2], String(process.env.API_KEY));\n");
  fs.writeFileSync(path.join(workspace, "reads.js"), "const a = process.env.API_KEY;\nconst b = process.env.NOT_LINKED_KEY;\n");
  fs.mkdirSync(path.join(workspace, ".vscode"));
  fs.writeFileSync(path.join(workspace, ".vscode", "settings.json"), JSON.stringify({ "envrune.path": envrune }));

  const env = { ...process.env, ENVRUNE_VAULT: vault, ENVRUNE_PASSWORD: "e2e-password-123" };
  // A vault with one secret; `envrune init` needs a terminal, so the Go
  // test helper creates it.
  execFileSync("go", ["run", "./test/integration/testdata/mkvault", vault, "e2e-password-123", "demo.api-key=sk-from-the-vault"], {
    cwd: path.resolve(__dirname, "..", "..", ".."),
    stdio: "inherit",
  });

  await runTests({
    extensionDevelopmentPath: path.resolve(__dirname, ".."),
    extensionTestsPath: path.resolve(__dirname, "suite.js"),
    launchArgs: [workspace, "--disable-extensions"],
    extensionTestsEnv: env,
  });
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
