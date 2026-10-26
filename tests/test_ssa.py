from pegrex.ssa import build_ssa


def test_parameter_assignment_and_load_renaming():
    report = build_ssa("def f(x):\n    y = x\n    x = y + 1\n    return x\n")
    function = next(row for row in report["functions"] if row["name"] == "f")
    values = {row["name"]: row["value"] for row in function["assignments"]}
    assert values["x#0"] == "parameter"
    assert values["y#1"] == "x#0"
    assert values["x#2"] == "y#1 + 1"
    assert function["returns"][0]["value"] == "x#2"


def test_branch_phi_versions_are_globally_unique():
    report = build_ssa("""def f(x, c):
    if c:
        x = 1
    else:
        x = 2
    y = x
    return y
""")
    rows = next(row for row in report["functions"] if row["name"] == "f")["assignments"]
    phi = [row for row in rows if row["phi"]]
    assert len(phi) == 1
    assert phi[0]["name"] == "x#4"
    assert phi[0]["sources"] == ["x#2", "x#3"]
    assert next(row for row in rows if row["name"] == "y#5")["value"] == "x#4"
    assert len({row["name"] for row in rows}) == len(rows)


def test_loop_phi_reports_bounded_widening_unknown():
    report = build_ssa("""def f(n):
    x = 0
    while n:
        x = x + 1
    return x
""")
    function = next(row for row in report["functions"] if row["name"] == "f")
    phis = [row for row in function["assignments"] if row["phi"]]
    assert len(phis) == 1
    assert phis[0]["value"].startswith("loop_phi(")
    assert any("widening" in row for row in function["unknowns"])


def test_unsupported_target_and_selection_are_explicit():
    report = build_ssa("""def f(x):
    a[0] = x
    with x:
        y = 1
""")
    report = build_ssa("""def f(x):
    a[0] = x
    return x
""", function="f")
    assert any("assignment target" in row for row in next(row for row in report["functions"] if row["name"] == "f")["unknowns"])
