---
name: pegrex-legacy
description: Modernize COBOL and Fortran to certified Python (or back). Use for bank/mainframe migrations where equivalence must be proven, not hoped.
---

# legacy modernization

- `modernize.modernize("prog.cob")` -> emitted Python + cross-language
  equivalence certificate. Executes; refusal carries a counterexample.
- `py2cobol.round_trip("f.py")` proves contract identity Python->COBOL.
- Identifiers canonicalize UPPERCASE in legacy frontends (documented
  convention). Rust/Go targets refuse to claim equivalence.
