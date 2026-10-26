# HEALTH.md - PegRex engine health check

Regenerate findings with `python pegrex.py health pegrex`, then update exact task dispositions and run `python tools/health_report.py`. Regenerate cognitive/contract evidence with `python tools/selfhost.py`. These are triaged analyzer tasks, not a count of confirmed vulnerabilities.

## Summary

| metric | value |
|---|---|
| engine files analyzed | 227 |
| total tasks | 779 |
| high severity | 0 |
| medium severity | 558 |
| low severity | 221 |
| undispositioned tasks | 0 |
| report SHA-256 | `2d7438cbc0b06cd1358c9861dd0fffa1c31013fbe3786142d1883176cec81274` |

See `docs/SELF.md` for current engine LOC, cognitive hotspots, contract extraction, and explicit UNKNOWN modules.

## Tasks by analyzer view

| view | tasks | dispositions |
|---|---|---|
| architecture | 240 | function-structure-backlog: 220, module-structure-backlog: 20 |
| refactor | 193 | function-structure-backlog: 190, intentional-process-state: 3 |
| security | 3 | generated-stub-secret-pattern: 1, operator-code-execution: 2 |
| testing | 343 | test-evidence-backlog: 343 |

## Dispositions

Every current task ID is assigned to a policy below. `maintenance-open` is explicit non-defect maintenance evidence, not a claim of completed remediation. `accepted-design` records intentional process-local configuration or memoization. `accepted-risk` is a documented operator trust boundary. `false-positive` records why the pattern is not a defect in its actual context.

| policy | status | tasks | rationale | evidence |
|---|---|---|---|---|
| function-structure-backlog | maintenance-open | 410 | Long-function and helper-extraction recommendations remain explicit maintenance work. They are not confirmed defects and must not be conflated with vulnerabilities. | docs/ARCHITECTURE.md<br>docs/PUBLIC_CONTRACTS.md<br>python run_tests.py |
| generated-stub-secret-pattern | false-positive | 1 | The scanner matches adjacent old/new client dictionary keys, not a credential value. Both expressions select the same generated Go client stub; no API key or secret is present. | pegrex/roundtrip.py:87-88<br>tests/test_roundtrip.py<br>No credentials, secrets, or external services are used by this code path |
| intentional-process-state | accepted-design | 3 | The solver backend selector, compiled grammar cache, and validated ZK group cache are intentional process-local configuration or memoization. Their behavior and thread-safety boundaries are covered without changing public contracts. | pegrex/smt.py:get_backend/set_backend<br>pegrex/work.py:_rules<br>pegrex/zkproof.py:_ensure_group<br>tests/test_work.py<br>tests/test_zkproof.py |
| module-structure-backlog | maintenance-open | 20 | Module-size thresholds identify candidates for future contract-preserving decomposition. Size alone is not a correctness or security defect; broad restructuring is intentionally deferred. | docs/ARCHITECTURE.md<br>docs/PUBLIC_CONTRACTS.md<br>python run_tests.py |
| operator-code-execution | accepted-risk | 2 | The concolic CLI intentionally loads and executes the operator-selected source before tracing it. This is an explicit code-execution interface, not a passive audit path; untrusted input requires an external isolated sandbox. | README.md:Intentional code execution boundaries<br>docs/PUBLIC_CONTRACTS.md<br>pegrex/commands/verification.py:_cmd_concolic<br>tests/test_production_hardening.py |
| test-evidence-backlog | maintenance-open | 343 | Static reference analysis found no direct test reference for these functions. This is a test-evidence gap, not proof that runtime coverage or indirect regression coverage is absent. | python run_tests.py<br>tests/ (direct and indirect regressions)<br>specs/pegrex_health.spec.json (static untested-function tasks) |

## Residual security-pattern tasks

| id | disposition | severity | location |
|---|---|---|---|
| T01 | operator-code-execution | MEDIUM | [commands/verification.py] [exec-detected] Detected the use of exec(). exec() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the progr |
| T02 | operator-code-execution | MEDIUM | [commands/verification.py] [python_exec_rule-exec-used] The application was found calling the `exec` function with a non-literal variable. If the
variable comes from user-supplied input, an advers |
| T559 | generated-stub-secret-pattern | LOW | [roundtrip.py] [generic-api-key] A gitleaks generic-api-key was detected which attempts to identify hard-coded credentials.  It is not recommended to store credentials in so |

## Gates

- `python run_tests.py`
- `python tools/selfhost.py --check`
- `python tools/health_report.py --check`
- `python tools/build_skills.py --check`

Machine-readable findings: `specs/pegrex_health.spec.json` (779 tasks). Exact dispositions: `specs/pegrex_health.dispositions.json`.
