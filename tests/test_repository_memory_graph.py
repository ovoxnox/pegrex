from pegrex.planner import plan_changes
from pegrex.repomemory import RepositoryMemory
from pegrex.semgraph import SemanticDependencyGraph


def project(tmp_path):
    (tmp_path / "helper.py").write_text("def helper(x):\n    if x > 0:\n        return x + 1\n    return 0\n")
    (tmp_path / "app.py").write_text("from helper import helper\n\ndef call(x):\n    return helper(x)\n")


def test_contract_memory_is_stable_persistent_and_queryable(tmp_path):
    project(tmp_path)
    memory = RepositoryMemory(tmp_path, boundaries={"app.py": ["helper"]})
    report = memory.refresh()
    assert memory.query_api("helper")[0]["contracts"]
    assert report["memory_identity"] == memory.refresh()["memory_identity"]
    assert not report["architecture"]["app.py"]["violations"]
    saved = tmp_path / "memory.json"
    memory.save(saved)
    loaded = RepositoryMemory.load(tmp_path, saved)
    assert loaded.payload() == memory.payload()
    assert loaded.invariants["helper.py::helper"]


def test_live_semantic_graph_maps_contracts_and_reverse_impact(tmp_path):
    project(tmp_path)
    memory = RepositoryMemory(tmp_path)
    memory.refresh()
    graph = SemanticDependencyGraph(memory)
    graph.refresh()
    caller = "app.py::call"
    helper = "helper.py::helper"
    assert helper in graph.dependencies(caller)
    assert caller in graph.impact(helper)
    contract_nodes = [key for key, row in graph.nodes.items() if row["kind"] == "contract"]
    assert contract_nodes
    assert any(row["kind"] == "invariant" for row in graph.nodes.values())
    (tmp_path / "helper.py").write_text("def helper(x):\n    if x > 0:\n        return x + 2\n    return 0\n")
    memory.refresh()
    update = graph.refresh()
    assert helper in update["changed"]
    assert caller in update["impacted"]


def test_risk_planner_penalizes_uncertainty_and_preserves_unknowns(tmp_path):
    project(tmp_path)
    memory = RepositoryMemory(tmp_path)
    memory.refresh()
    graph = SemanticDependencyGraph(memory)
    graph.refresh()
    plan = plan_changes(graph, [
        {"id": "risky", "target": "helper.py::helper", "benefit": 1,
         "uncertainty": 1, "proof_effort": 2},
        {"id": "focused", "target": "app.py::call", "benefit": 1,
         "uncertainty": 0, "proof_effort": 1},
        {"id": "missing", "target": "app.py::call"},
    ])
    assert plan["candidates"][0]["id"] == "focused"
    assert plan["candidates"][-1]["status"] == "unknown"
    assert plan["unknowns"]
