# PegRex PathContract v2 — normative interchange specification

**Status:** v1.1.6 specification. This document defines the portable record shape and the minimum semantics that producers must state. It does not retroactively strengthen legacy `PathContract` rows or prove that a frontend extracted them soundly.

## 1. Meaning and limits

A path contract describes one path-conditioned observable behavior for one source artifact. A record is a semantic description, not a theorem. JSON shape validation alone never establishes source equivalence, guard satisfiability, effect completeness, exception reachability, or termination.

Every analysis consumer MUST preserve `unknown` and incomplete evidence. It MUST NOT reinterpret a missing field, unsupported construct, parser refusal, timeout, or unvisited source region as purity, normal return, termination, or proof.

## 2. Source coordinates

`source.sha256` is the lowercase SHA-256 digest of the exact UTF-8 source bytes. `source.span` is zero-based and half-open `[start, end)` measured in Unicode code points of the decoded source text. `unit` MUST be `unicode-codepoint`; `convention` MUST be `zero-based-half-open`. Byte-based parser offsets MUST be converted at the frontend boundary. A span MUST satisfy `0 <= start <= end`; source-bound validation additionally requires `end <= len(decoded_source)`.

A path or function name is provenance only; neither changes the meaning of a span. Consumers comparing records from different source hashes MUST NOT assume the coordinates refer to the same text.

## 3. Record fields

The authoritative machine schema is `pegrex/jsonschemas/path-contract.v2.json`.

- `schema` / `schema_version`: fixed identifiers `pegrex.path-contract.v2` / `2`.
- `source`: source hash and span; optional `path` is informational.
- `function`: optional qualified function name.
- `guards`: normalized guard expressions in the producer's declared frontend fragment. Strings are not solver certificates and do not imply that the guard is satisfiable.
- `outcome.kind`: one of `return`, `raise`, `terminate`, `diverge`, `unknown`. `raise` requires an `exception_type`. A return expression is only a textual representation unless separately checked.
- `effects`: deduplicated declared effect categories. An empty list means “no effects represented by this producer”, not proof of purity unless the producer's coverage claim is separately justified. Use `unknown` when effect coverage cannot be established.
- `nondeterministic`: whether behavior is declared nondeterministic. If unknown, add an uncertainty to `unknowns`; do not encode unknown as `false`.
- `termination.status`: `proven`, `refuted`, `unknown`, or `not-claimed`. `proven` / `refuted` require separate evidence whose scope and checker are identified outside this shape-only validator.
- `numeric_semantics`: explicit integer model, overflow behavior, and floating-point model. `unknown` is not a wildcard that permits equivalence claims.
- `unknowns`: non-empty explanations of unsupported syntax, missing parser, resource limits, unvisited regions, unresolved solver questions, or incomplete effects/termination information.

## 4. Numeric semantics

Integer models are `unbounded`, `fixed-width-signed`, `fixed-width-unsigned`, or `unknown`. Overflow behavior is `wrap`, `trap`, `undefined`, `not-applicable`, or `unknown`. Floating-point behavior is `ieee754`, `decimal`, `not-applicable`, or `unknown`. A producer MUST NOT compare or merge numeric outcomes across differing models without a separate validated translation or equivalence argument.

## 5. Evidence and verdicts

Finite-domain proof certificates establish equivalence only for the explicitly enumerated domains and the exact expression fragment accepted by the independent checker. Such evidence MUST retain the domain, checker/schema version, assignment count, and proof digest. It MUST NOT be promoted to unbounded source equivalence. A sampled execution or differential test is evidence of an observed behavior, not proof of universal equivalence.

Any unsupported operation, incomplete domain, bound overflow, parser failure, timeout, or disagreement MUST produce `unknown` or `refuted` according to the actual evidence; it MUST NOT produce `proven` by default.

## 6. Compatibility and migration

The existing `pegrex.core.models.PathContract` and its `pegrex.core.v1` serialization remain unchanged for compatibility. Conversion to v2 is an explicit adapter operation; missing semantic fields must be filled with `unknown` / `not-claimed`, never guessed. The v2 validator checks schema shape and vocabulary only and returns `is_proof: false` even for valid records.

## 7. Required conformance tests

Producers/consumers should test: Unicode source spans; hash mismatch; malformed/negative spans; exception outcomes without types; unsupported effect values; duplicate effects; unknown propagation; distinct integer/overflow models; and rejection of claims that exceed finite-domain evidence. CI must keep these tests in the mandatory suite.
