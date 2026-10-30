# HEALTH.md - PegRex engine health check

Regenerate findings with `python pegrex.py health pegrex`, then update exact task dispositions and run `python tools/health_report.py`. Regenerate cognitive/contract evidence with `python tools/selfhost.py`. These are triaged analyzer tasks, not a count of confirmed vulnerabilities.

## Summary

| metric | value |
|---|---|
| engine files analyzed in stored scan | 265 |
| total tasks | 907 |
| high severity | 0 |
| medium severity | 623 |
| low severity | 284 |
| undispositioned tasks | 0 |
| report SHA-256 | `865843099355299a1ad1bd61babf0f4f203738f04f72cb0f51042f7fc7657621` |

See `docs/SELF.md` for current engine LOC, cognitive hotspots, contract extraction, and explicit UNKNOWN modules.

**Source-census status: current.** The stored scan covers all 265 eligible source files.

## Tasks by analyzer view

| view | tasks | dispositions |
|---|---|---|
| architecture | 281 | function-structure-backlog: 256, module-structure-backlog: 25 |
| documentation | 28 | documentation-backlog: 28 |
| refactor | 227 | function-structure-backlog: 224, intentional-process-state: 3 |
| testing | 371 | test-evidence-backlog: 371 |

## Dispositions

Every current task ID is assigned to a policy below. `maintenance-open` is explicit non-defect maintenance evidence, not a claim of completed remediation. `accepted-design` records intentional process-local configuration or memoization. `accepted-risk` is a documented operator trust boundary. `false-positive` records why the pattern is not a defect in its actual context.

| policy | status | tasks | rationale | evidence |
|---|---|---|---|---|
| documentation-backlog | maintenance-open | 28 | Missing public-symbol docstrings are explicit documentation maintenance. They do not imply unsafe behavior; public operations and trust boundaries are separately documented and regression-tested. | docs/PUBLIC_CONTRACTS.md<br>python run_tests.py<br>specs/pegrex_health.spec.json (static documentation tasks) |
| function-structure-backlog | maintenance-open | 480 | Long-function and helper-extraction recommendations remain explicit maintenance work. They are not confirmed defects and must not be conflated with vulnerabilities. | docs/ARCHITECTURE.md<br>docs/PUBLIC_CONTRACTS.md<br>python run_tests.py |
| intentional-process-state | accepted-design | 3 | The solver backend selector, compiled grammar cache, and validated ZK group cache are intentional process-local configuration or memoization. Their behavior and thread-safety boundaries are covered without changing public contracts. | pegrex/smt.py:get_backend/set_backend<br>pegrex/work.py:_rules<br>pegrex/zkproof.py:_ensure_group<br>tests/test_work.py<br>tests/test_zkproof.py |
| module-structure-backlog | maintenance-open | 25 | Module-size thresholds identify candidates for future contract-preserving decomposition. Size alone is not a correctness or security defect; broad restructuring is intentionally deferred. | docs/ARCHITECTURE.md<br>docs/PUBLIC_CONTRACTS.md<br>python run_tests.py |
| test-evidence-backlog | maintenance-open | 371 | Static reference analysis found no direct test reference for these functions. This is a test-evidence gap, not proof that runtime coverage or indirect regression coverage is absent. | python run_tests.py<br>tests/ (direct and indirect regressions)<br>specs/pegrex_health.spec.json (static untested-function tasks) |

## Residual security-pattern tasks

| id | disposition | severity | location |
|---|---|---|---|
| none | n/a | n/a | no active security-pattern tasks |

## Gates

- `python run_tests.py`
- `python tools/selfhost.py --check`
- `python tools/health_report.py --check`
- `python tools/build_skills.py --check`

Machine-readable findings: `specs/pegrex_health.spec.json` (907 tasks). Exact dispositions: `specs/pegrex_health.dispositions.json`.
