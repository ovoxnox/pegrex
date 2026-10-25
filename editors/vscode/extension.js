// PegRex VS Code extension -- dependency-free LSP client over stdio.
// No vscode-languageclient, no node_modules: Content-Length framing and the
// four LSP messages we need (initialize / didOpen+didChange / hover /
// codeLens / executeCommand) are implemented inline.
const vscode = require("vscode");
const { spawn } = require("child_process");

let server = null;
let nextId = 1;
const pending = new Map(); // id -> {resolve, reject, timer}
let outBuf = Buffer.alloc(0);
let serverReady = false;
const opened = new Set();

function send(message) {
  if (!server || server.killed) return;
  const body = Buffer.from(JSON.stringify(message), "utf8");
  server.stdin.write(`Content-Length: ${body.length}\r\n\r\n`);
  server.stdin.write(body);
}

function request(method, params, timeoutMs = 15000) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`pegrex LSP timeout on ${method}`));
    }, timeoutMs);
    pending.set(id, { resolve, reject, timer });
    send({ jsonrpc: "2.0", id, method, params });
  });
}

function notify(method, params) {
  send({ jsonrpc: "2.0", method, params });
}

function onMessage(msg) {
  if (msg.id !== undefined && pending.has(msg.id)) {
    const { resolve, reject, timer } = pending.get(msg.id);
    clearTimeout(timer);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(msg.error.message || "pegrex LSP error"));
    else resolve(msg.result);
    return;
  }
  // server-initiated requests/notifications: we advertise nothing inbound,
  // but answer any request so the server never blocks on us.
  if (msg.method && msg.id !== undefined) {
    send({ jsonrpc: "2.0", id: msg.id, result: null });
  }
}

function onStdout(chunk) {
  outBuf = Buffer.concat([outBuf, chunk]);
  for (;;) {
    const headerEnd = outBuf.indexOf("\r\n\r\n");
    if (headerEnd < 0) return;
    const header = outBuf.slice(0, headerEnd).toString("utf8");
    const m = /Content-Length:\s*(\d+)/i.exec(header);
    if (!m) { // unparseable frame: drop the header line, keep the rest
      outBuf = outBuf.slice(headerEnd + 4);
      continue;
    }
    const len = parseInt(m[1], 10);
    const frameStart = headerEnd + 4;
    if (outBuf.length < frameStart + len) return;
    const body = outBuf.slice(frameStart, frameStart + len).toString("utf8");
    outBuf = outBuf.slice(frameStart + len);
    try { onMessage(JSON.parse(body)); }
    catch (_) { /* a malformed server frame is ignored, never crashes us */ }
  }
}

function didOpen(document) {
  const uri = document.uri.toString();
  if (opened.has(uri)) return;
  opened.add(uri);
  notify("textDocument/didOpen", {
    textDocument: {
      uri,
      languageId: document.languageId,
      version: document.version,
      text: document.getText(),
    },
  });
}

function startServer(pythonPath, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      pythonPath,
      ["-c", "import sys; from pegrex.lsp import serve; serve(sys.stdin, sys.stdout.buffer)"],
      { cwd: cwd || undefined, stdio: ["pipe", "pipe", "pipe"] }
    );
    let stderr = "";
    let settled = false;
    const bail = (why) => {
      if (!settled) { settled = true; reject(new Error(why)); }
    };
    child.on("error", (e) => bail(`${e.code || e.message}`));
    child.stderr.on("data", (d) => {
      stderr += d.toString();
      if (!settled && stderr.length > 4000) stderr = stderr.slice(-4000);
    });
    child.on("exit", (code) => {
      if (!settled) bail(`pegrex LSP exited early (code ${code}): ${stderr.trim()}`);
    });
    child.stdout.on("data", onStdout);
    server = child;
    const rootUri = cwd ? vscode.Uri.file(cwd).toString() : null;
    request("initialize", {
      processId: process.pid,
      rootUri,
      capabilities: { textDocument: { codeLens: true, hover: true } },
    }).then((result) => {
      if (!settled) {
        settled = true;
        notify("initialized", {});
        serverReady = true;
        resolve(result);
      }
    }, (e) => bail(e.message));
  });
}

async function activate(context) {
  const config = vscode.workspace.getConfiguration("pegrex");
  const pythonPath = config.get("pythonPath", "python");
  const folder = vscode.workspace.workspaceFolders
    ? vscode.workspace.workspaceFolders[0].uri.fsPath
    : undefined;
  try {
    await startServer(pythonPath, folder);
  } catch (e) {
    vscode.window.showErrorMessage(
      `pegrex not installed or not importable (${e.message}). ` +
      "pip install pegrex, or set pegrex.pythonPath to an interpreter that has it."
    );
    return; // clean death: providers are never registered
  }

  const active = vscode.window.activeTextEditor;
  if (active && active.document.languageId === "python") didOpen(active.document);

  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor((ed) => {
      if (ed && ed.document.languageId === "python") didOpen(ed.document);
    }),
    vscode.workspace.onDidChangeTextDocument((ev) => {
      const uri = ev.document.uri.toString();
      if (opened.has(uri) && ev.document.languageId === "python") {
        notify("textDocument/didChange", {
          textDocument: { uri, version: ev.document.version },
          contentChanges: [{ text: ev.document.getText() }],
        });
      }
    })
  );

  context.subscriptions.push(
    vscode.languages.registerHoverProvider("python", {
      async provideHover(document, position) {
        didOpen(document);
        try {
          const res = await request("textDocument/hover", {
            textDocument: { uri: document.uri.toString() },
            position: { line: position.line, character: position.character },
          });
          if (!res || !res.contents) return null;
          const md = new vscode.MarkdownString(res.contents.value || "");
          return new vscode.Hover(md);
        } catch (e) {
          return null; // a refusal is not a pop-up storm
        }
      },
    })
  );

  context.subscriptions.push(
    vscode.languages.registerCodeLensProvider("python", {
      async provideCodeLenses(document) {
        didOpen(document);
        try {
          const lenses = await request("textDocument/codeLens", {
            textDocument: { uri: document.uri.toString() },
          });
          if (!Array.isArray(lenses)) return [];
          return lenses.map((l) => {
            const range = new vscode.Range(
              new vscode.Position(l.range.start.line, l.range.start.character),
              new vscode.Position(l.range.end.line, l.range.end.character)
            );
            const cmd = l.command || { title: "pegrex", arguments: [] };
            return new vscode.CodeLens(range, {
              title: cmd.title,
              command: "pegrex.showContracts",
              arguments: cmd.arguments || [],
            });
          });
        } catch (e) {
          return [];
        }
      },
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("pegrex.showContracts", async (...args) => {
      try {
        const res = await request("workspace/executeCommand", {
          command: "pegrex.showContracts",
          arguments: args,
        });
        if (typeof res === "string") {
          vscode.window.showInformationMessage(res, { modal: false });
        }
      } catch (e) {
        vscode.window.showErrorMessage(`pegrex: ${e.message}`);
      }
    })
  );
}

function deactivate() {
  if (server && !server.killed) {
    try { send({ jsonrpc: "2.0", id: nextId++, method: "shutdown", params: null }); } catch (_) {}
    server.kill();
  }
  server = null;
  serverReady = false;
  opened.clear();
}

module.exports = { activate, deactivate };
