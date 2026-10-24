# Tools

The unified CLI is `python pegrex.py <command>` at the project root.

| Command | Function | Underlying |
|---|---|---|
| `audit <file>` | security audit (patterns + taint + SCA) | `tools/secaudit.py` |
| `spec <src> <name>` | AI spec schema (multi-opus) | `tools/mkspec/` |
| `index <dir>` | repo arch index | `tools/repokit.py` |
| `bundle <src>` | portable verification bundle | `tools/repokit.py` |
| `gaps` / `tests` | coverage gaps / synthesized tests | `pegrex/coverage.py` + `testsynth.py` |
| `budget <file>` | complexity budget gate | `pegrex/budget.py` |
| `lint` / `extract` | grammar hygiene | `tools/grammar_lint.py` / `extract_grammar.py` |
| `induce` | grammar induction demo | `pegrex/induce.py` |
| `health <path>` | self code-health spec | `tools/mkspec/` |
| `verify <spec>` | translation certificate | `pipeline.py` |
| `serve` | JSON-lines service | `service.py` |

Library entry points (for scripts): `tools.secaudit.audit(path)` returns
findings as dicts; `tools.repokit.repo_index` / `verification_bundle`;
`tools.mkspec.core.run_analyzers` / `run_opus` / `render_spec`.
