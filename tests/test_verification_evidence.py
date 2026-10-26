import ast
import hashlib

from pegrex.analyzermutation import mutation_controls, standard_negative_controls
from pegrex.compilerdiff import verify_compiler_change
from pegrex.pathrefine import refine_paths
from pegrex.proofreplay import replay_certificate
from pegrex.resourcebounds import analyze_resource_bounds
from pegrex.smt import auto_feasible
from pegrex.smtlib import crosscheck_smtlib, export_smtlib
from pegrex.statemachine import check_state_machine
from pegrex.witness import minimize_symbolic_witness


def test_path_pruning_retains_feasibility_and_dominance_evidence():
    infeasible = refine_paths([(["(x < 0)", "(x > 0)"], "bad"), ([], "ok")])
    assert len(infeasible["kept"]) == 1
    assert infeasible["removed"][0]["reason"] == "infeasible"
    dominated = refine_paths([([], "x"), (["(x > 0)"], "x")])
    assert len(dominated["kept"]) == 1
    assert dominated["removed"][0]["reason"] == "constraint-dominated"
    assert dominated["removed"][0]["evidence"]["subsumed_by"]


def test_symbolic_witness_minimization_revalidates_constraints_and_execution():
    result = minimize_symbolic_witness(["(x >= 3)"], {"x": 100},
                                       reproduce=lambda row: row["x"] >= 3)
    assert result["confirmed"] and result["minimized"]["x"] == 3
    assert any(not row["accepted"] for row in result["attempts"])
    bad = minimize_symbolic_witness(["(x >= 3)"], {"x": 2})
    assert bad["verdict"] == "unknown" and not bad["confirmed"]


def test_analyzer_mutation_requires_baseline_and_detects_weakening():
    result = mutation_controls([{"name": "solver-infeasibility", "component": "solver",
        "baseline": lambda: auto_feasible(["(x < 0)", "(x > 0)"]),
        "weakened": lambda: True, "detects": lambda value: value is False}])
    assert result["killed"] == 1 and result["verdict"] == "proved"
    survived = mutation_controls([{"name": "parser", "baseline": lambda: True,
        "weakened": lambda: True, "detects": lambda value: value}])
    assert survived["survived"] == 1 and survived["verdict"] == "refuted"


def _certificate():
    contracts = [{"constraints": [], "outcome": "x"}]
    identity = hashlib.sha256(b'x').hexdigest()
    return {"schema": "pegrex.certificate.v1", "schema_version": 1,
            "verdict": "proved", "claim": "equivalent", "unknowns": [],
            "before_source_sha256": identity, "after_source_sha256": identity,
            "evidence": {"before_contracts": contracts, "after_contracts": [{"constraints": [], "outcome": "x"}]}}


def test_solver_free_replay_checks_proof_and_optional_source_identities():
    result = replay_certificate(_certificate(), before_source="x", after_source=b"x")
    assert result["replayed"] and result["solver_used"] is False
    import copy
    forged = copy.deepcopy(_certificate()); forged["evidence"]["after_contracts"][0]["outcome"] = "y"
    assert not replay_certificate(forged)["replayed"]
    assert replay_certificate(_certificate(), before_source="z")["verdict"] == "unknown"


def test_smtlib_export_and_independent_z3_crosscheck():
    exported = export_smtlib(["(2*x + y <= 4)", "(x >= 1)"])
    assert exported["status"] == "complete" and "(set-logic QF_LIA)" in exported["script"]
    assert crosscheck_smtlib(exported)["verdict"] == "sat"
    unknown = export_smtlib(["opaque(x)"])
    assert unknown["status"] == "unknown" and not unknown["script"]


def test_protocol_model_check_proof_refutation_and_bound_unknown():
    transitions = [{"id": "open", "when": {"state": "new"}, "set": {"state": "open"}}]
    invariants = [{"id": "states", "variable": "state", "operator": "in",
                   "value": ["new", "open"]}]
    proved = check_state_machine([{"state": "new"}], transitions, invariants)
    assert proved["verdict"] == "proved"
    bad = check_state_machine([{"state": "new"}], transitions,
        [{"id": "closed", "variable": "state", "value": "new"}])
    assert bad["verdict"] == "refuted" and bad["counterexample"]["trace"]
    bounded = check_state_machine([{"state": "new"}], transitions, invariants, max_depth=0)
    assert bounded["verdict"] == "unknown" and bounded["bound"]["reached"]


def test_resource_bounds_are_limited_to_proven_fragments():
    source = """def f(n):
    for i in range(n):
        x = []
"""
    result = analyze_resource_bounds(source)
    row = result["functions"][0]
    assert row["worst_case_complexity"] == "O(n)" and row["verdict"] == "unknown"
    terminating = analyze_resource_bounds("""def f(x):
    while x > 0:
        x -= 1
""")
    assert terminating["functions"][0]["termination"] == "proved"
    unknown = analyze_resource_bounds("""def f(x):
    while x:
        pass
""")
    assert unknown["verdict"] == "unknown"


def test_compiler_upgrade_differential_has_three_valued_semantics():
    source = """def f(x):
    if x >= 0:
        return x + 1
    return 0
"""
    same = verify_compiler_change(source, lambda text: text,
                                  lambda text: text.replace("x + 1", "(x + 1)"))
    assert same["verdict"] == "proved"
    changed = verify_compiler_change(source, lambda text: text,
                                     lambda text: text.replace("x + 1", "x + 2"))
    assert changed["verdict"] == "refuted"


def test_builtin_parser_solver_and_rule_negative_controls_are_killed():
    result = standard_negative_controls()
    assert {row["component"] for row in result["controls"]} == {"parser", "solver", "rules"}
    assert result["killed"] == 3 and result["survived"] == 0
