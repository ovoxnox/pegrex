"""Policy-as-code and mutation-based bypass tests for the agent harness."""
from __future__ import annotations
from .analyzermutation import mutation_controls
from .harness import check_plan, default_policy
SCHEMA="pegrex.harness-policy-tests.v1"

def run_harness_policy_suite(*, base_dir=None) -> dict:
    """Implement run harness policy suite with the module's explicit API and failure semantics."""
    safe=check_plan([{"tool":"shell","argv":["git","status"]}],base_dir=base_dir)
    attacks=[("raw-shell",{"tool":"shell","argv":"git status"}),
      ("shell-chain",{"tool":"shell","argv":["git","status;id"]}),
      ("quoted-metacharacter",{"tool":"shell","argv":["git","'status|id'"]}),
      ("environment-expansion",{"tool":"shell","argv":["git","$HOME"]}),
      ("absolute-path",{"tool":"shell","argv":["git","/tmp"]}),
      ("unicode-confusable",{"tool":"shell","argv":["ɡit","status"]}),
      ("indirect-launcher",{"tool":"shell","argv":["python","-m","pytest"]}),
      ("policy-mutation-push",{"tool":"shell","argv":["git","push","origin","main"]})]
    cases=[{"name":name,"component":"harness-policy",
      "baseline":lambda action=action: check_plan([action],default_policy(),base_dir=base_dir),
      "weakened":lambda action=action: check_plan([action],[{"effect":"allow","tool":"*"}],base_dir=base_dir),
      "detects":lambda result: result["safe"] is False} for name,action in attacks]
    report=mutation_controls(cases)
    report["mutation_report_schema"] = report.get("schema")
    report["schema"] = SCHEMA
    report["suite_schema"] = SCHEMA
    report["mutation_verdict"]=report["verdict"]
    report["safe_baseline_allowed"]=safe["safe"] is True
    # Syntax/launcher confinements must survive an allow-all policy mutation;
    # policy-only denials must be killed by that same mutation.
    expected={name:("survived" if name in {
        "raw-shell","shell-chain","quoted-metacharacter","environment-expansion",
        "absolute-path","unicode-confusable"} else "killed") for name,_ in attacks}
    failures=[row["name"] for row in report["controls"]
              if row["status"]!=expected[row["name"]]]
    report["expected_mutation_status"]=expected
    report["expectation_failures"]=failures
    if not safe["safe"] or any(row["status"]=="unknown" for row in report["controls"]):
        report["verdict"]="unknown"
        if not safe["safe"]:report["unknowns"].append("canonical safe argv was not allowed")
    else:report["verdict"]="refuted" if failures else "proved"
    return report
