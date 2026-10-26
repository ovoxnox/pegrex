"""
orgtwin - digital twin of the engineering org.

twin ownership x compliance findings x cognitive over-budget, joined by team. 
"Which team misses SOC2 and is over budget?" is one query over one
join -- and teams the twin has no data about are unknown, never clean."""

from __future__ import annotations

from .cognitive import cognitive_complexity
from .compliance import audit_gdpr, audit_soc2
from .twin import build as twin_build


def org_report(root, controls=(), budget=7, team_of=None):
    """team_of: fn(owner_name) -> team (default: owner IS the team)."""
    team_of = team_of or (lambda owner: owner or "unowned")
    twin = twin_build(root)
    teams = {}
    for fn, path in twin["files"].items():
        owner = twin["owners"].get(fn)
        team = team_of(owner)
        row = teams.setdefault(team, {"functions": 0, "over_budget": [],
                                      "compliance": [], "unknown": []})
        row["functions"] += 1
        src = open(path, encoding="utf-8").read()
        rep = cognitive_complexity(src, budget=budget)
        if rep.get("verdict") != "ok":
            row["unknown"].append(fn)
            continue
        for f in rep["functions"]:
            if f["complexity"] > budget and f["refactor_plans"]:
                row["over_budget"].append(f["name"])
        for finding in audit_gdpr(src):
            row["compliance"].append({"function": fn, **finding})
        for finding in audit_soc2(src, list(controls)):
            row["compliance"].append({"function": fn, **finding})
    for team, row in teams.items():
        row["misses_soc2"] = any("soc2" in str(c).lower()
                                 or "gdpr" in str(c).lower()
                                 for c in row["compliance"])
        row["at_risk"] = bool(row["over_budget"]) and row["misses_soc2"]
    return {"teams": teams}


def who_is_at_risk(report):
    """Implement who is at risk with the module's explicit API and failure semantics."""
    return sorted(t for t, r in report["teams"].items() if r["at_risk"])


def who_is_unknown(report):
    """Implement who is unknown with the module's explicit API and failure semantics."""
    return {t: r["unknown"] for t, r in report["teams"].items() if r["unknown"]}
