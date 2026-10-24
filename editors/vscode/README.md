# PegRex for VS Code

Path contracts from the [PegRex](https://github.com/ovoxnox/pegrex) symbolic-execution
engine, live in the editor. The extension is a **dependency-free** LSP client:
`extension.js` implements Content-Length framing and the handful of LSP
messages the pegrex server speaks directly against `child_process` — there is
no `vscode-languageclient`, no bundled node_modules, nothing to audit but the
one file.

## Requirements

- Python with `pegrex` importable (e.g. the repo checkout opened as the
  workspace, or `pip install pegrex` into that interpreter).
- VS Code 1.85.0 or newer.

## Install

Manual (no build step, nothing to compile):

```sh
mkdir -p ~/.vscode/extensions/pegrex-vscode-0.1.0
cp -r editors/vscode/* ~/.vscode/extensions/pegrex-vscode-0.1.0/
# reload VS Code
```

Or package it with `vsce package` and install the resulting `.vsix` via
"Extensions: Install from VSIX".

## Configuration

- `pegrex.pythonPath` (default `"python"`) — the interpreter used to launch
  the server. If pegrex is not importable there, the extension shows
  "pegrex not installed — pip install pegrex …" and deactivates cleanly; it
  never pretends to analyze.

## What works

- **Hover** on Python code: the function's path contracts
  (`constraints → result` per path).
- **CodeLens** above each top-level `def`: `pegrex: N paths · P proved / U
  unknown`, computed by the engine per document version.
- **Command** `pegrex.showContracts` (click the CodeLens): the contract lines
  in a message box.

## What refuses — honestly

- Paths whose constraints fall outside the engine's linear-arithmetic
  fragment (non-linear arithmetic, opaque conditions) are shown as
  **unknown**, never counted as proved. A function the engine cannot analyze
  says so in the lens title.
- Non-Python files, virtual buffers, and missing engine installs get nothing
  or a named error — no fabricated badges.

## Honesty note

This extension bundles **zero** node dependencies; the only runtime module it
requires is `vscode` itself, injected by the editor. The protocol layer is
~60 lines of framing code you can read in one sitting.
