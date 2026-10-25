# HEALTH.md - pegrex engine health check

Regenerate the machine-readable findings with `python pegrex.py health pegrex`; regenerate the cognitive and contract self-audit with `python tools/selfhost.py`. These are analyzer tasks to triage, not confirmed vulnerabilities.

## summary

| metric | value |
|---|---|
| engine files analyzed | 1 |
| total tasks | 1804 |
| high severity | 212 |
| medium severity | 1275 |
| low severity | 317 |
| engine LOC | 18696 |
| modules with contracts | 57 |
| modules where contracts unknown | 99 |

## tasks by opus

| opus | tasks | severities |
|---|---|---|
| architecture | 167 | MEDIUM 14, LOW 153 |
| documentation | 149 | LOW 149 |
| refactor | 105 | MEDIUM 105 |
| security | 721 | HIGH 212, MEDIUM 494, LOW 15 |
| testing | 662 | MEDIUM 662 |

## high-severity security findings (top 15 of 212)

| id | title | location |
|---|---|---|
| T01 | [acp.py] [open-never-closed] file object opened without corresponding close | 70 |
| T02 | [acp.py] [useless-literal-set] `$X` is uselessly assigned twice inside the creation of the set | 104, 108 |
| T03 | [acp.py] [use-json-response] Use JsonResponse instead | 156, 195 |
| T04 | [acp.py] [use-jsonify] flask.jsonify() is a Flask helper method which handles the correct  settings for returning JSON from Flask routes | 156, 195 |
| T05 | [antihalluc.py] [open-never-closed] file object opened without corresponding close | 42, 58 |
| T06 | [api.py] [use-json-response] Use JsonResponse instead | 50 |
| T07 | [api.py] [use-jsonify] flask.jsonify() is a Flask helper method which handles the correct  settings for returning JSON from Flask routes | 50 |
| T08 | [api.py] [useless-literal-set] `$X` is uselessly assigned twice inside the creation of the set | 69, 80, 94, 106, 117, 120, 121 |
| T09 | [api.py] [dangerous-system-call] Found user-controlled data used in a system call. This could allow a malicious actor to execute commands. Use the 'subprocess' module instea | 93 |
| T10 | [api.py] [dangerous-system-call-audit] Found dynamic content used in a system call. This is dangerous if external data can reach this function call because it allows a malicious a | 93 |
| T11 | [api.py] [strict-cmd-injection] command sink with unknown taint (strict) | 93 |
| T12 | [attest.py] [use-json-response] Use JsonResponse instead | 19 |
| T13 | [attest.py] [use-jsonify] flask.jsonify() is a Flask helper method which handles the correct  settings for returning JSON from Flask routes | 19 |
| T14 | [autopilot.py] [use-json-response] Use JsonResponse instead | 153, 156 |
| T15 | [autopilot.py] [use-jsonify] flask.jsonify() is a Flask helper method which handles the correct  settings for returning JSON from Flask routes | 153, 156 |

## cognitive hotspots

See `docs/SELF.md` for the current per-module cognitive hotspots, contract-extraction refusals, and refactor-plan counts.

## remediation order

1. Triage the 212 high-severity security findings above and in the machine-readable spec; verify each before fixing or annotating it.
2. Testing coverage: 662 MEDIUM tasks, prioritizing modules with extracted contracts.
3. Documentation: 149 LOW tasks; hotspots first.
4. Refactor: 105 MEDIUM maintainability tasks; coordinate them with the cognitive hotspots in `SELF.md`.
5. Architecture: 167 tasks from the structure analyzer.

## gates (run before any remediation lands)

- `python run_tests.py` (560 tests)
- `python tools/selfhost.py --check` (complete self-audit freshness)
- `python tools/build_skills.py --check` (reproducible, duplicate-free skill archive)

Full machine-readable spec: `specs/pegrex_health.spec.json` (1804 tasks).
