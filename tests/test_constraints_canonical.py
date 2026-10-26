from pegrex.constraints import (cache_info, canonicalize_constraints, clear_cache,
                                constraint_hash, implies)


def test_integer_and_scaled_constraints_share_semantic_identity():
    assert constraint_hash(["x < 1"]) == constraint_hash(["x <= 0"])
    assert constraint_hash(["2*x + -2*y <= 4"]) == constraint_hash(["x - y <= 2"])
    assert constraint_hash(["x >= 1", "x <= 1"]) == constraint_hash(["x = 1"])


def test_fractional_integer_semantics_are_not_changed_for_prettier_hash():
    assert constraint_hash(["2*x <= 3"]) != constraint_hash(["x <= 1"])


def test_implication_cache_uses_canonical_semantics():
    clear_cache()
    first = implies(["x <= 0"], ["x < 1"])
    second = implies(["2*x <= 0"], ["x <= 0"])
    assert first["status"] == second["status"] == "entailed"
    assert first["conclusions"] == second["assumptions"]
    assert cache_info()["hits"] >= 1


def test_opaque_constraints_are_never_promoted_to_proof():
    result = implies(["f(x) > 0"], ["f(x) >= 0"])
    assert result["status"] == "unknown"
    assert implies(["f(x) > 0"], ["f(x) > 0"])["status"] == "entailed"


def test_constraint_report_is_versioned_and_explicit():
    report = canonicalize_constraints(["x < 2"]).to_dict()
    assert report["schema"] == "pegrex.canonical-constraints.v1"
    assert report["identity_kind"] == "semantic-qf-lia"
    assert report["identity"].startswith("sha256:")
