"use strict";

// Runs inside the test VS Code; see run.js.

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const vscode = require("vscode");

async function waitFor(check, what, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const value = await check();
    if (value) {
      return value;
    }
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
}

async function run() {
  const workspace = vscode.workspace.workspaceFolders[0].uri.fsPath;
  const extension = vscode.extensions.all.find((e) => e.packageJSON.name === "envrune" && e.extensionPath.includes("vscode"));
  assert.ok(extension, "the extension is loaded");
  const api = await extension.activate();
  await api.ready;

  // Commands.
  const commands = await vscode.commands.getCommands(true);
  for (const name of ["envrune.unlock", "envrune.lock", "envrune.runCommand", "envrune.linkVariable"]) {
    assert.ok(commands.includes(name), `${name} is registered`);
  }

  // Projects, from `envrune inspect`, without values.
  const info = [...api.projects.byPath.values()][0];
  assert.equal(info.project, "demo", JSON.stringify(info));
  const variable = info.environments[0].variables[0];
  assert.equal(variable.name, "API_KEY");
  assert.equal(variable.reference, "demo.api-key");
  assert.equal(variable.stored, true);
  assert.ok(!JSON.stringify(info).includes("sk-from-the-vault"), "inspect never returns values");

  // A warning on a variable envrune.yml does not link, and none on one it does.
  const document = await vscode.workspace.openTextDocument(path.join(workspace, "reads.js"));
  await vscode.window.showTextDocument(document);
  const diagnostics = await waitFor(() => {
    const found = vscode.languages.getDiagnostics(document.uri).filter((d) => d.source === "EnvRune");
    return found.length > 0 && found;
  }, "diagnostics");
  assert.equal(diagnostics.length, 1);
  assert.match(diagnostics[0].message, /NOT_LINKED_KEY is not linked/);
  assert.equal(document.getText(diagnostics[0].range), "NOT_LINKED_KEY");

  // A debug session with "envrune": true gets the secret in its environment.
  const output = path.join(os.tmpdir(), `envrune-debug-${Date.now()}.txt`);
  const started = await vscode.debug.startDebugging(vscode.workspace.workspaceFolders[0], {
    type: "node",
    request: "launch",
    name: "EnvRune e2e",
    program: path.join(workspace, "app.js"),
    args: [output],
    envrune: true,
  });
  assert.ok(started, "the debug session started");
  const written = await waitFor(() => fs.existsSync(output) && fs.readFileSync(output, "utf8"), "the debugged program");
  assert.equal(written, "sk-from-the-vault");
  fs.rmSync(output, { force: true });
  console.log("EnvRune e2e: all checks passed");
}

module.exports = { run };
