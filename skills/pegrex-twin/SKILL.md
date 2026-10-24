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
