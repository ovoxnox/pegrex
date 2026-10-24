"""
legalci - contract-deadline CI artifact.

legal.py's parsed obligations become a CI report: clauses with deadlines
become rows; deadlines inside the warning window (default 14 days,
relative to an explicit 'today' for determinism) are warnings; missed
obligations are failures. The artifact states its as-of date and counts
what the parser could not read -- no invented precision."""

from __future__ import annotations

from datetime import date, timedelta

from .legal import parse_clauses


def report_clauses(clauses, today=None, warn_days=14):
    """Clause-level report. A deadline without a base date is not
    evaluable -- it is 'info' with a reason, never fake-future (a deadline
    relative to 'today' can never be missed; that default was the lesson)."""
    today = today or date.today()
    clauses = list(clauses)
    warn_before = today + timedelta(days=warn_days)
    rows = []
    failures = warnings = 0
    for c in clauses:
        deadline = None
        if c.get("deadline") is not None:
            base = c.get("base_date") or today
            if isinstance(base, str):
                base = date.fromisoformat(base)
            deadline = base + timedelta(days=c["deadline"])
        status = "info"
        note = None
        if c.get("deadline") is not None and c.get("base_date") is None:
            note = "no base date -- deadline not evaluable"
        if deadline is not None and c.get("base_date") is not None:
            if deadline < today:
                status = "failure"
                failures += 1
            elif deadline <= warn_before:
                status = "warning"
                warnings += 1
        row = {"party": c.get("party"),
               "deadline": str(deadline) if deadline else None,
               "status": status}
        if note:
            row["note"] = note
        rows.append(row)
    return {"as_of": str(today), "clauses": rows,
            "failures": failures, "warnings": warnings,
            "passed": failures == 0}


def ci_report(text, today=None, warn_days=14):
    today = today or date.today()
    clauses = parse_clauses(text)
    shalls = text.lower().count(" shall ") + text.lower().count(" must ")
    out = report_clauses(clauses, today=today, warn_days=warn_days)
    out["unparsed"] = max(shalls - len(clauses), 0)
    return out
