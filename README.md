# pegrex v1.0.0


![](assets/report.png)


**A self-contained symbolic-execution and syntactic-analysis engine** that
turns source code in 15 languages into mathematical specifications for AI
agents — and *refuses loudly* rather than guessing. Every claim is either
proven by an executable certificate or reported with its counterexample.

`parse -> solve/prove -> abstract -> execute -> emit/verify -> repair -> serve`

Full contract extraction (paths → results) is certified for Python, COBOL, and Fortran; the other tree-sitter languages parse to CSTs through the bridge. Solidity gets both contract extraction and audit/insurance treatment.

**PegRex** is a self-contained symbolic-execution and syntactic-analysis engine that turns source code into mathematical specifications for AI agents — **parse, solve, prove, abstract, execute, emit, verify, repair, serve** — where every claim is either proven; refuted with a concrete counterexample; or honestly reported as unknown. It speaks fifteen-plus languages, exposes sixty-five commands, 331 unit tests, 17 agent skills — and audits itself in public via a regenerated SELF.md that CI refuses to let go stale.

**Tree-sitter frontends (full CST → contracts)**
 - Nine bindings: Python, Go, Rust, Julia, Kotlin, Zig, Solidity, Vyper, JavaScript, TypeScript, AssemblyScript. 
 - The bridge's language map also routes lua and c (those resolve via the tree_sitter_language_pack when installed 

**Native legacy frontends (certified, no grammar needed)** hand-built parsers producing the same contract tuples as every other language, with machine-checked cross-language equivalence (a COBOL absval and a Fortran absval verify as identical). An offline tree-sitter mock layer makes these parse through the standard bridge too.

 - COBOL (.cob/.cbl/.cobol)
 - Fortran (.f90/.f95/.f03/.f08)

**Domain-specific languages**
 - SQL (SELECT subset with OR groups — SQL↔ORM equivalence checking)
 - Circom (ZK circuits — under-constrained signal auditing)

**Grammar-text formats (the LPegRex .gram compiler)**
 - JSON, C11, CSV, URL, INI, S-expressions, Go-subset, MIR, MLIR, Vyper-subset, agent grammars — compiled by the split pegrex/lpegc/ compiler into executable pattern trees.


## The Security Engine

**Defense in depth, each layer certified with negative controls that must refuse:**

    · SAST core — 691 pattern rules + 87 taint rules over adjacency-indexed CFGs; parallel audits; budget-aware triage; 760 converted semgrep rules; offline OSV scanning;
    · Taint, three-valued — every flow is safe, vulnerable, or UNKNOWN; never "no path found" as "verified.";
    · ZK auditing — under-constrained Circom detection; '<\--' without '===' and unconstrained outputs are named;
    · Autonomous bug bounty — discover the guard, solve a concrete payload by Fourier-Motzkin, delta-debug the minimal witness, repair under a payload-killed verifier (an unguarded sink post-fix is worse, never "fixed") — and the whole loop is policy-gated before execution by the agent safety harness (default-deny, deny precedence, first refusal stops the plan);
    · Compliance as code — GDPR findings that name the flow; SOC2 control presence; legal deadlines without a base date are "not evaluable," never fake-future;
    · Infrastructure verification — Zelkova-style can (principal, action, resource) with explicit-deny precedence; wildcard-admin and public-bucket findings;
    · Insurance oracle — premiums ordered by verified overflow risk, HMAC-signed, labelled a toy heuristic: honesty in the price tag;
    · Distribution trust — signed manifests, SLSA attestations; the Sigstore seam refuses offline rather than pretend publication.

## The (A)Schema & Specification Engine

**The contract is the atom: every function becomes path contracts — (constraints) → result — and every other engine consumes or produces them.**

    · specgen — the AI spec schema (multi-opus): specifications as agent-consumable data, not prose;
    · modernize / py2cobol — legacy modernization in both directions with machine-checked contract identity across language spaces;
    · apicontract — an OpenAPI schema is the shared contract; the Python server and Go client are each checked against it; drift is named, never smoothed;
    · refine — # requires:/# ensures: comments discharged per path; undischarged is reported, never assumed;
    · specmine — Daikon-style candidates classified proven / likely / dropped; mining proposes, never asserts;
    · nlspec → antihalluc — English claims become formal candidates, then the anti-hallucination compiler emits code from the contract IR and verifies it: a false sentence ships nothing;
    · sqlrel — SQL and ORM agree only when proven equivalent; OR-conditions compare group-wise; sampled production query logs carry their sample size on every verdict.


 -  **ir.py lower_condition():** *any condition → typed IR; loud CondError, never a silent regex guess*
 -  **linsolve.py:** *LinearBackend.learn/entails*

## What it does

Given a function, pegrex enumerates its path contracts —
`(constraints) -> result` pairs — then lets you *do* things with them:

| capability | module
|---|---
| typed expression IR (the m76 seam: `a+1 < b`, calls, fields) | `pegrex/ir.py`
| Fourier-Motzkin multi-var linear arithmetic + entailment | `pegrex/linsolve.py`
| differential solver testing (bounds vs FM + filed findings)
| proof-carrying certificates (linear-combination witnesses) | `pegrex/proofs.py`
| symbolic memory: bounds + aliasing verdicts | `pegrex/memory.py`
| Houdini loop invariants + single-fixpoint property checking (not full IC3/PDR: no frame sequence, no CTI/propagation) | `invariants.py` / `pdr.py`
| octagon domain (closure, widening, FM-differential) | `pegrex/octagon.py`
| termination ranking functions | `pegrex/rank.py`
| per-language integer-overflow semantics (Rust/C/Solidity) | `pegrex/overflow.py`
| **certified transpilation**: contract IR -> real Python + proof | `emitter.py`, `transpiler.py`
| concolic execution (trace, flip branches, confirm) | `pegrex/concolic.py`
| Hypothesis strategies from path constraints | `strategies.py`
| refinement contracts as comments (Dafny-lite) | `refine.py`
| spec mining (Daikon-style, classified proven/likely/dropped) | `specmine.py`
| NL -> spec -> proof (claims proven, dropped, or refused) | `nlspec.py`
| CEGIS repair loop + integrated evidence pipeline | `cegis.py`, `chain.py`
| semantic diff / `verify_patch` (proof or counterexample) | `semantics.py`
| e-graphs with oracle-refused rewriting + node-var patterns | `eggx.py`
| SQL <-> ORM equivalence | `sqlrel.py`
| bytecode VM (loops with ranked termination) | `vm.py`
| veritesting state-merging via FM projection | `veritest.py`
| agent endpoints: A2A (JSON-lines) + LSP (hover contracts) | `a2a.py`, `lsp.py`
| context compression for LLM calls | `compress.py`
| deterministic agent benchmark + verified-pair exporter | `benchmark.py`, `trainer.py`
| signed skill marketplace (HMAC manifests) | `marketplace.py`
| cross-language API contracts (OpenAPI schema) | `apicontract.py`
| **COBOL frontend** (native contracts, refinement, verify_patch) | `cobolfront.py`
| **Fortran frontend** (result convention, cross-language equivalence) | `fortranfront.py`
| offline tree-sitter mocks + vendor seam (COBOL/Fortran) | `tsmock.py`
| legacy modernization factory (COBOL/Fortran -> Python + equivalence certificate) | `modernize.py`
| three-valued results everywhere (proved/refuted/unknown, machine-audited) | `tv.py`
| ZK-circuit auditing (under-constrained Circom) | `zk.py`
| IaC verification, Zelkova-style (IAM can() + findings) | `iac.py`
| AI safety harness (agent plans refused pre-execution) | `harness.py`
| bug-bounty agent (discover -> solve -> minimize PoC) | `bounty.py`
| GDPR/SOC2 compliance as code (taint findings) | `compliance.py`
| ML graph verification (quant/prune equivalence, bounded) | `mlgraph.py`
| digital twin codebase graph (NL via path math) | `twin.py`
| probabilistic path analysis (trace frequencies rank tests) | `probpath.py`
| SLSA-style attestations (offline-honest Sigstore seam) | `slsa.py`
| time-bounded verify-or-refuse API (deadline -> unknown) | `vapi.py`
| cognitive complexity for Python (complexipy-faithful reimplementation) | `cognitive.py`
| twin + cognitive queries ("which functions are over budget?") | `twin.py`
| cognitive-budget CI gate (`--fail-on-over`) | `cli.py`
| unified taint/facts/twin graph, one-traversal queries | `graph.py`
| autopwn: policy-gated discover -> solve -> repair loop | `autopwn.py`
| probabilistic deadline allocation (verdicts carry coverage) | `priorverify.py`
| round-trip modernization (Python -> COBOL, contract identity) | `py2cobol.py`
| legal-deadline CI artifact (honest base-date semantics) | `legalci.py`
| SQL OR-conditions + sampled migration equivalence | `sqlrel.py`
| **anti-hallucination compiler** (NL -> code -> proof; refuses) | `antihalluc.py`
| **org twin** (teams x compliance x complexity) | `orgtwin.py`
| hybrid RAG: local embeddings + BM25, offline (served path -- rag.py's chunking delegates scoring here) | `hybridrag.py`
| adversarial self-play: bounty fuzzes the harness policy, bypasses become permanent negative controls | `selfplay.py`
| e-graph performance oracle: ranks oracle-proven-equivalent expressions by op-count, refuses what it can't independently connect | `perfgolf.py`
| natural-language contract chat for PR review: proven / refuted-with-witness / unknown PR-comment replies | `prchat.py`
| self-certifying package registry: specmine-proven properties signed + tracked; regressions refused by name | `registry.py`
| continuity: verify the engine against its own prior version, function-by-function, proof or named counterexample | `continuity.py`

## Library

```
from pegrex import facade          # the whole surface in one import
out = facade.verify_patch("a.py", "b.py")   # proof or counterexample
```

## CLI

```
python pegrex.py index --out <out> <dir>   # repo arch index
python pegrex.py audit FILE                # 782-rule (694 pattern + 88 taint) + taint audit
python pegrex.py spec --dir <PATH>         # AI spec schema (multi-opus)
python pegrex.py contracts FILE            # path contracts
python pegrex.py cognitive <file>          # cognitive complexity + refactor plans
python pegrex.py rosetta <spec>  N-        # N-way cross-language equivalence (semantic diff)
python pegrex.py modernize <file>          # legacy (COBOL/Fortran) -> target with equivalence certificate
python pegrex.py roundtrip --print-cobol   # Python -> COBOL round-trip with contract identity
python pegrex.py insure --verify <file>    # quote/verify a Solidity overflow-risk premium
python pegrex.py rules --json              # rule catalog summary
python pegrex.py osvscan                   # dependency vulnerability scan (OSV)
python pegrex.py cisec <file>              # CI/CD pipeline security analysis
python pegrex.py verify-patch              # proof or counterexample for two sources
python pegrex.py bundle <PATH> <source>    # portable verification bundle
python pegrex.py compile-nl <text> <file>  # anti-hallucination compiler: NL -> code -> proof
python pegrex.py autopwn                   # policy-gated discover/solve/repair loop
python pegrex.py bounty  <file>            # discover/solve/minimize a PoC for a sink
python pegrex.py verify-patch BEFORE AFTER # proof or counterexample
python pegrex.py export --format <format>  # export findings (json/csv/html)
python pegrex.py compress                  # LLM context compression
python pegrex.py explain <file>            # explain a function as math
python pegrex.py callgraph --dir <PATH>    # function-call graph (DOT/ASCII)
python pegrex.py coverage --dir <PATH>     # path coverage overlay + gaps
python pegrex.py caps <file>               # infer capabilities + sandbox policy
python pegrex.py diff A B                  # semantic diff
python pegrex.py budget --dir <PATH>       # complexity budget gate
python pegrex.py emit FILE [--run]         # certified code from contracts
python pegrex.py check FILE                # discharge requires/ensures comments
python pegrex.py compliance                # GDPR data-flow + optional SOC2 control audit
python pegrex.py harness-check <plan>      # check an agent plan JSON against the safety policy
python pegrex.py strategy <file>           # Hypothesis strategies from path constraints
python pegrex.py mine FILE                 # mine likely invariants
python pegrex.py concolic <file>           # trace a run and flip a branch
python pegrex.py probpath <spec>           # path frequencies + priorities from traces
python pegrex.py mlcheck: <spec>           # quant/prune equivalence from a JSON spec
python pegrex.py rank "i <= n" --delta i=1 # termination ranking
python pegrex.py transpile FILE python     # certified Python target
python pegrex.py bench                     # agent-edit benchmark
python pegrex.py tests --lcov <lcov> <src> # synthesize tests from coverage gaps
python pegrex.py serve|acp|mcp|a2a|lsp     # protocol endpoints
```

## The one rule

Every engine surface follows the same discipline: **prove it, or refuse loudly**. 
Undischarged contracts are reported, never assumed; opaque
fragments degrade to `unknown`/`maybe`; certificates carry negative controls
that must refuse; `verify_patch` returns a counterexample, not a shrug.

## Repository layout

```
pegrex/        engine (pegrex/pegc/ holds the PegRex
                   compiler split: parser.py / compiler.py / diagnostics.py) 
                   (125 modules, stdlib+pydantic)
tests/         70 unit-test modules (326 tests)
examples/      .gram formats + walkthroughs
tools/         repo-facing scripts (secaudit, mkspec, ...)
skills/        agent SKILL packs
docs/          README.md, HEALTH.md, SELF.md (the self-audit)
```

## The self-hosting proof

`python tools/selfhost.py` regenerates `docs/SELF.md` -- the twin, cognitive-complexity, and contract reports of pegrex/ *by pegrex itself* (436 functions, published refusals included).

## Mission

 - Turn source code into mathematical specifications that AI agents can trust -- and make "trust" mean something provable.

## One-liner

 - parse -> solve/prove -> abstract -> execute -> emit/verify -> repair -> serve -> audit itself.

## Invariants (the whole law)

1. - Three-valued everywhere: PROVED, REFUTED, UNKNOWN. Unknown is first-class; "no path found" is never "verified".
2. - Refusal is a feature: anything outside the certified fragment is REFUSED loudly, never guessed.
3. - Negative controls are sacred: weakening one scores minus infinity (golfbench), and CI fails on it.
4. - The engine audits itself: docs/SELF.md is regenerated by tools/selfhost.py and --check fails the build when it goes stale.
5. - Offline honesty: absent toolchains (z3, xxhash, Go, Sigstore) are certified refusals, not silent fallbacks.


## Genesis: Born from LPegRex

  *- a Python rewrite of Sérgio Medeiros's PEG-based regex extension to LPeg/Lua: a packrat engine with error labels and a grammar-text compiler:* **The seed discipline — parse faithfully, refuse ambiguity — became the spine of everything after.**

 **-  Reimplemented: with local philosophy**
      · CEGIS;
      · octagons;
      · SLSA attestation;
      · KLEE-lite memory;
      · Houdini and IC3/PDR frames;
      · complexipy's cognitive complexity;
      · a Z3-class QF_LIA solver by Fourier-Motzkin;
      · DRAT-style proof certificates;
      · Zelkova-style IAM;
      · Daikon-style mining;
      · Dafny-lite contracts;
      · egg-style e-graphs with oracle-refused rewrites;
      · DeepPoly-lite bounds for quantized neural graphs;
      · offline tree-sitter conformance mocks.

**Became: the engine that audits everything — and audits itself**
   · a modernization factory (COBOL/Fortran → certified Python, both directions);
   · an anti-hallucination compiler (English → provably-correct code);
   · an insurance oracle pricing from verified overflow risk.


## Status notes (honest)

- **transpiler**: production for Multilingual targets (emitter + proof).
- **codegen.emit_rust_stub**: the portable-data half by design.
- **mini_llm**: the designed zero-dependency fallback; use `hybridrag` for retrieval.
