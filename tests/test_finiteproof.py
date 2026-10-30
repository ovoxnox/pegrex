from pegrex.finiteproof import SCHEMA, check_finite_domain_proof
from pegrex.kernel import check_certificate
from pegrex.proofreplay import replay_certificate


def var(name):
    return {"op": "var", "name": name}


def const(value):
    return {"op": "const", "value": value}


def binary(op, left, right):
    return {"op": op, "left": left, "right": right}


def proof(before, after, domains=None):
    return {"schema": SCHEMA, "schema_version": 1,
            "claim": "finite-domain-equivalent",
            "domains": domains if domains is not None else {"x": [-2, -1, 0, 1, 2]},
            "before": before, "after": after}


def cert(p, verdict="proved"):
    return {"schema": "pegrex.certificate.v1", "schema_version": 1,
            "verdict": verdict, "claim": "finite-domain-equivalent",
            "unknowns": [], "evidence": {"finite_domain_proof": p}}


def test_finite_domain_checker_proves_identity_and_replay_agrees():
    p = proof(binary("add", var("x"), const(0)), var("x"))
    result = check_finite_domain_proof(p)
    assert result["checked"] and result["verdict"] == "proved"
    assert result["assignments_checked"] == 5
    assert check_certificate(cert(p))["verdict"] == "proved"
    replay = replay_certificate(cert(p))
    assert replay["replayed"] and replay["verdict"] == "proved"


def test_finite_domain_checker_returns_counterexample_for_difference():
    p = proof(binary("add", var("x"), const(1)), var("x"))
    result = check_finite_domain_proof(p)
    assert result["checked"] and result["verdict"] == "refuted"
    assert result["counterexample"]
    assert not check_certificate(cert(p, "proved"))["checked"]
    assert replay_certificate(cert(p, "refuted"))["verdict"] == "refuted"


def test_finite_domain_checker_fails_closed_on_unknown_ops_and_limits():
    bad = proof({"op": "call", "name": "evil"}, const(0))
    assert check_finite_domain_proof(bad)["verdict"] == "unknown"
    huge = proof(var("x"), var("x"), {"x": list(range(64)), "y": list(range(64)), "z": list(range(64))})
    assert check_finite_domain_proof(huge)["verdict"] == "unknown"


def test_finite_domain_checker_checks_types_and_boolean_logic():
    expr = {"op": "ite", "cond": binary("ge", var("x"), const(0)),
            "then": var("x"), "else": {"op": "neg", "arg": var("x")}}
    p = proof(expr, {"op": "ite", "cond": binary("ge", var("x"), const(0)),
                     "then": var("x"), "else": binary("mul", const(-1), var("x"))})
    assert check_finite_domain_proof(p)["verdict"] == "proved"
    wrong = proof({"op": "not", "arg": const(1)}, const(0))
    assert check_finite_domain_proof(wrong)["verdict"] == "unknown"
