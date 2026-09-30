"use strict";

const vscode = require("vscode");
const path = require("node:path");
const cli = require("./src/cli.js");
const { findEnvReferences, unlinked, suggestReference } = require("./src/envrefs.js");

/** @returns {string} the envrune executable from the settings */
function binary() {
  return vscode.workspace.getConfiguration("envrune").get("path") || "envrune";
}

/** Runs an envrune command in a terminal, where it can ask for a password. */
function inTerminal(args, cwd) {
  const terminal = vscode.window.createTerminal({ name: "EnvRune", cwd });
  terminal.show();
  terminal.sendText([binary(), ...args.map(quote)].join(" "));
}

function quote(arg) {
  return /^[\w@%+=:,./-]+$/.test(arg) ? arg : `"${arg.replace(/(["\\$`])/g, "\\$1")}"`;
}

// ---------------------------------------------------------------- projects

/** Caches `envrune inspect` for each envrune.yml in the workspace. */
class Projects {
  constructor() {
    this.byPath = new Map();
    this.changed = new vscode.EventEmitter();
    this.onDidChange = this.changed.event;
  }

  async refresh() {
    const files = await vscode.workspace.findFiles("**/envrune.yml", "**/node_modules/**", 50);
    const next = new Map();
    await Promise.all(
      files.map(async (file) => {
        const dir = path.dirname(file.fsPath);
        try {
          next.set(file.fsPath, await cli.inspect(binary(), dir));
        } catch (error) {
          next.set(file.fsPath, { path: file.fsPath, project: path.basename(dir), error: error.message, environments: [], commands: [] });
        }
      }),
    );
    this.byPath = next;
    this.changed.fire();
  }

  /** The project whose folder contains file, the deepest one first. */
  forFile(file) {
    let best;
    for (const info of this.byPath.values()) {
      const dir = path.dirname(info.path);
      if ((file === dir || file.startsWith(dir + path.sep)) && (!best || dir.length > path.dirname(best.path).length)) {
        best = info;
      }
    }
    return best;
  }
}

// ---------------------------------------------------------------- tree view

class TreeProvider {
  constructor(projects) {
    this.projects = projects;
    this.changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this.changed.event;
    projects.onDidChange(() => this.changed.fire());
  }

  getTreeItem(node) {
    return node;
  }

  getChildren(node) {
    if (!node) {
      return [...this.projects.byPath.values()].map((info) => {
        const item = new vscode.TreeItem(info.project, vscode.TreeItemCollapsibleState.Expanded);
        item.description = vscode.workspace.asRelativePath(path.dirname(info.path));
        item.tooltip = info.error || info.path;
        item.iconPath = new vscode.ThemeIcon(info.error ? "warning" : "key");
        item.contextValue = "project";
        item.info = info;
        return item;
      });
    }
    const info = node.info;
    if (node.contextValue === "project") {
      const children = info.environments.map((environment) => {
        const item = new vscode.TreeItem(environment.environment, vscode.TreeItemCollapsibleState.Collapsed);
        item.description = environment.environment === info.default_env ? "default" : "";
        item.iconPath = new vscode.ThemeIcon("symbol-namespace");
        item.contextValue = "environment";
        item.info = info;
        item.environment = environment;
        return item;
      });
      if (info.commands.length > 0) {
        const commands = new vscode.TreeItem("Commands", vscode.TreeItemCollapsibleState.Collapsed);
        commands.iconPath = new vscode.ThemeIcon("run-all");
        commands.contextValue = "commands";
        commands.info = info;
        children.push(commands);
      }
      return children;
    }
    if (node.contextValue === "environment") {
      return node.environment.variables.map((variable) => {
        const item = new vscode.TreeItem(variable.name);
        let icon = "circle-outline";
        if (!variable.reference) {
          item.description = "not linked";
          icon = "warning";
        } else if (variable.stored === false) {
          item.description = `${variable.reference} (missing in the vault)`;
          icon = "error";
        } else {
          item.description = variable.reference;
          icon = variable.stored ? "pass" : "circle-outline";
        }
        item.iconPath = new vscode.ThemeIcon(icon);
        item.tooltip = new vscode.MarkdownString([variable.description, variable.how_to_get && `How to get it: ${variable.how_to_get}`].filter(Boolean).join("\n\n") || variable.name);
        item.contextValue = variable.reference ? "variable" : "unlinkedVariable";
        item.info = info;
        item.variable = variable;
        item.environmentName = node.environment.environment;
        return item;
      });
    }
    if (node.contextValue === "commands") {
      return info.commands.map((command) => {
        const item = new vscode.TreeItem(command.name);
        item.description = command.run;
        item.iconPath = new vscode.ThemeIcon("play");
        item.contextValue = "command";
        item.command = { command: "envrune.runCommand", title: "Run", arguments: [item] };
        item.info = info;
        item.commandName = command.name;
        return item;
      });
    }
    return [];
  }
}

// ---------------------------------------------------------------- status bar

function statusBar(context) {
  const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  item.command = "envrune.menu";
  const update = async () => {
    try {
      const folder = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      const s = await cli.status(binary(), folder);
      if (s.unlocked) {
        const hours = Math.floor(s.remaining_seconds / 3600);
        const minutes = Math.floor((s.remaining_seconds % 3600) / 60);
        item.text = `$(unlock) EnvRune ${hours > 0 ? `${hours}h` : `${minutes}m`}`;
        item.tooltip = `Unlocked until ${new Date(s.expires).toLocaleTimeString()}. Click to lock.`;
      } else if (s.keychain) {
        item.text = "$(unlock) EnvRune";
        item.tooltip = "Unlocked through the system keychain.";
      } else if (!s.exists) {
        item.text = "$(key) EnvRune";
        item.tooltip = "No vault yet. Run `envrune init` in a terminal.";
      } else {
        item.text = "$(lock) EnvRune";
        item.tooltip = "Locked. Click to unlock for 8 hours.";
      }
      item.state = s;
      item.show();
    } catch (error) {
      item.text = "$(warning) EnvRune";
      item.tooltip = error.message;
      item.show();
    }
  };
  update();
  const timer = setInterval(update, 15_000);
  context.subscriptions.push(item, { dispose: () => clearInterval(timer) }, vscode.window.onDidChangeWindowState((s) => s.focused && update()));
  return { item, update };
}

// ---------------------------------------------------------------- diagnostics

function diagnostics(context, projects) {
  const collection = vscode.languages.createDiagnosticCollection("envrune");
  context.subscriptions.push(collection);
  const check = (document) => {
    const settings = vscode.workspace.getConfiguration("envrune");
    if (!settings.get("diagnostics.enabled", true) || document.uri.scheme !== "file") {
      collection.delete(document.uri);
      return;
    }
    const info = projects.forFile(document.uri.fsPath);
    if (!info || info.error) {
      collection.delete(document.uri);
      return;
    }
    const linked = new Set(info.environments.flatMap((e) => e.variables.filter((v) => v.reference).map((v) => v.name)));
    const text = document.getText();
    const missing = unlinked(findEnvReferences(text, document.languageId), linked, settings.get("diagnostics.ignore", []));
    collection.set(
      document.uri,
      missing.map((ref) => {
        const range = new vscode.Range(document.positionAt(ref.index), document.positionAt(ref.index + ref.length));
        const diagnostic = new vscode.Diagnostic(range, `${ref.name} is not linked in envrune.yml, so envrune run will not set it.`, vscode.DiagnosticSeverity.Warning);
        diagnostic.source = "EnvRune";
        diagnostic.code = "unlinked-variable";
        return diagnostic;
      }),
    );
  };
  const checkAll = () => vscode.workspace.textDocuments.forEach(check);
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(check),
    vscode.workspace.onDidSaveTextDocument(check),
    vscode.workspace.onDidCloseTextDocument((d) => collection.delete(d.uri)),
    projects.onDidChange(checkAll),
  );
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      ["javascript", "javascriptreact", "typescript", "typescriptreact", "vue", "svelte", "astro", "python"],
      {
        provideCodeActions(document, _range, ctx) {
          return ctx.diagnostics
            .filter((d) => d.source === "EnvRune")
            .map((d) => {
              const name = document.getText(d.range);
              const action = new vscode.CodeAction(`Link ${name} with EnvRune…`, vscode.CodeActionKind.QuickFix);
              action.diagnostics = [d];
              action.command = { command: "envrune.linkVariable", title: "Link", arguments: [{ name, file: document.uri.fsPath }] };
              return action;
            });
        },
      },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
  );
}

// ---------------------------------------------------------------- debugging

/**
 * Adds the variables of an environment to a debug session whose launch
 * configuration has "envrune": true or { "env": "staging" }. The values go
 * into the session's environment in memory; no file is written.
 */
function debugging(context) {
  const provider = {
    async resolveDebugConfigurationWithSubstitutedVariables(folder, config) {
      if (!config.envrune) {
        return config;
      }
      const environment = typeof config.envrune === "object" ? config.envrune.env : undefined;
      const cwd = config.cwd || folder?.uri.fsPath;
      try {
        const values = await cli.variables(binary(), cwd, environment);
        // Values set in launch.json win, as with envFile.
        config.env = { ...values, ...(config.env || {}) };
        return config;
      } catch (error) {
        const choice = await vscode.window.showErrorMessage(`EnvRune could not provide the variables: ${error.message}`, "Unlock for 8 hours");
        if (choice) {
          inTerminal(["unlock", "--ttl", "8h"], cwd);
        }
        return undefined; // cancels the launch
      }
    },
  };
  context.subscriptions.push(vscode.debug.registerDebugConfigurationProvider("*", provider));
}

// ---------------------------------------------------------------- commands

function commands(context, projects, bar) {
  const folderOf = (node) => (node?.info ? path.dirname(node.info.path) : vscode.workspace.workspaceFolders?.[0]?.uri.fsPath);
  const register = (name, fn) => context.subscriptions.push(vscode.commands.registerCommand(name, fn));

  register("envrune.refresh", () => projects.refresh());
  register("envrune.unlock", () => inTerminal(["unlock", "--ttl", "8h"], folderOf()));
  register("envrune.lock", async () => {
    try {
      await cli.run(binary(), ["lock"]);
      vscode.window.showInformationMessage("EnvRune forgot the vault key.");
    } catch (error) {
      vscode.window.showErrorMessage(error.message);
    }
    bar.update();
  });
  register("envrune.menu", async () => {
    const unlocked = bar.item.state?.unlocked;
    const choice = await vscode.window.showQuickPick(
      [
        unlocked ? { label: "$(lock) Lock now", id: "lock" } : { label: "$(unlock) Unlock for 8 hours", id: "unlock" },
        { label: "$(pulse) Run envrune doctor", id: "doctor" },
        { label: "$(refresh) Refresh projects", id: "refresh" },
      ],
      { placeHolder: "EnvRune" },
    );
    if (choice) {
      vscode.commands.executeCommand(`envrune.${choice.id}`);
    }
  });
  register("envrune.doctor", (node) => inTerminal(["doctor"], folderOf(node)));
  register("envrune.runCommand", async (node) => {
    let name = node?.commandName;
    let info = node?.info;
    if (!name) {
      const picks = [...projects.byPath.values()].flatMap((i) => i.commands.map((c) => ({ label: c.name, description: `${i.project}: ${c.run}`, info: i })));
      const choice = await vscode.window.showQuickPick(picks, { placeHolder: "Run a command from envrune.yml" });
      if (!choice) {
        return;
      }
      name = choice.label;
      info = choice.info;
    }
    inTerminal([name], path.dirname(info.path));
  });
  register("envrune.linkVariable", async (arg) => {
    const name = arg?.variable?.name || arg?.name;
    const info = arg?.info || (arg?.file && projects.forFile(arg.file));
    if (!name || !info) {
      return;
    }
    const environment = arg?.environmentName || info.default_env;
    const reference = await vscode.window.showInputBox({
      prompt: `Vault reference for ${name} in ${environment}`,
      value: suggestReference(info.project, name, environment),
      validateInput: (value) => (/^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*$/.test(value) ? undefined : "Use lowercase words separated by dots."),
    });
    if (reference) {
      // link offers to store the value when the reference is new; the
      // terminal is where it can ask for it without echoing.
      inTerminal(["link", name, reference, "--env", environment], path.dirname(info.path));
    }
  });
}

// ---------------------------------------------------------------- activation

function activate(context) {
  const projects = new Projects();
  const bar = statusBar(context);
  context.subscriptions.push(vscode.window.registerTreeDataProvider("envrune.projects", new TreeProvider(projects)));
  diagnostics(context, projects);
  debugging(context);
  commands(context, projects, bar);

  const watcher = vscode.workspace.createFileSystemWatcher("**/envrune.yml");
  const refresh = () => projects.refresh();
  context.subscriptions.push(watcher, watcher.onDidChange(refresh), watcher.onDidCreate(refresh), watcher.onDidDelete(refresh));
  // Terminals are where the vault gets unlocked, locked, and changed.
  context.subscriptions.push(vscode.window.onDidCloseTerminal(() => { refresh(); bar.update(); }));
  // The end-to-end tests read the projects through this.
  return { projects, ready: refresh() };
}

function deactivate() {}

module.exports = { activate, deactivate };
