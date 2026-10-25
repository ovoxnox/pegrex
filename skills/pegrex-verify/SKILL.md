---
name: pegrex-verify
description: Prove patches and diffs correct with verify_patch, semantic_diff, and the CEGIS repair loop. Use when an agent proposes an edit and you must certify it or refuse with a counterexample.
---

# verification

- `verify_patch(before.py, after.py)` -> {"verified": bool,
  "counterexample": {"inputs": {...}}} | None. NEVER trust an edit that
  was not verified; a counterexample is a gift, not a failure.
- `semantic_diff(a.py, b.py)` compares path contracts, not lines.
  `refine.discharge_source` checks `# requires:` / `# ensures:` comments.
- Repair loop: `cegis.repair(src, proposer)` feeds counterexamples back
  to the proposer until verified or the budget is spent.
- Three-valued everywhere: wrap results with `tv.wrap` -- a crash, a
  timeout, or a missing result is UNKNOWN, never proved.
- Inspect `python pegrex.py soundness --language ID` before interpreting a
  result. Its manifest states the supported fragment and unsupported cases;
  parser availability and process completion are not proof.
- Use `PathEnumerator.enumerate_bounded()` and
  `LinearBackend.entails_with_status()` for resource-aware verification. A path
  cap, solver query/deadline budget, or per-file timeout yields UNKNOWN and no
  partial path set; legacy boolean entailment fails closed.
- Security scans are evidence reports, not proofs of safety. Preserve their exact
  source, rule-catalog, parser, and OSV snapshot identities. Offline OSV misses
  are UNKNOWN; SARIF suppressions require a reviewer justification and remain
  visible to audit rather than erasing the finding.
