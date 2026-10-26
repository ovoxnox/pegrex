---
name: pegrex-twin
description: Query the codebase twin (call graph, ownership, guards, cognitive complexity) and the org twin (teams x compliance x complexity). Use for "which functions/teams are at risk?" questions.
---

# digital twins

- `twin.ask(twin, "which functions can reach db_execute?")` answers
  with guards attached. Unknown question shapes refuse loudly.
- `twin.cognitive_report(twin, budget=N)` + `orgtwin.org_report(root)`:
  "which team misses SOC2 and is over budget?" is one join. Teams with
  no data are UNKNOWN, never clean.

## Repository evidence and operational traces
- `build_repository_twin` joins calls, ownership, contracts, dependencies,
  supplied change history, and declared exposures under a content identity.
  `twin_function_risk` separates function impact from module dependency impact.
- `detect_architecture_drift` reports unintended imports and internal calls;
  incomplete repository evidence stays UNKNOWN.
- `replay_incident` maps runtime events to feasible/unknown/infeasible contract
  paths and evaluates patch candidates without applying them.
- `prioritize_symbolic_paths` retains and prioritizes unseen feasible paths.
  Traces do not prove unseen paths impossible; path-cap results have no partial
  ranking.
- `simulate_change_impact` evaluates proposed changes only in staging and reports
  potentially invalidated contracts, policies, generated clients, flows, and
  downstream modules. It never applies the patch or authorizes a merge.
