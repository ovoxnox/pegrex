import hashlib
import json
import threading
import time
from pathlib import Path

from pegrex.a2atasks import A2ATaskProtocol, execute_task
from pegrex.contextcompiler import compile_agent_context
from pegrex.decisionlog import DecisionLog, explain_decision
from pegrex.harness import default_policy
from pegrex.repomemory import RepositoryMemory
from pegrex.specproposals import evaluate_proposal, propose_spec


def wait_for(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.005)
    raise AssertionError("condition was not reached before timeout")


def test_context_compiler_retains_repository_evidence_and_unknowns(tmp_path):
    (tmp_path / "app.py").write_text("def f(x):\n    return x + 1\n")
    (tmp_path / "test_app.py").write_text("def test_f():\n    assert f(1) == 2\n")
    memory = RepositoryMemory(tmp_path)
    memory.refresh()
    memory.limitations.append("manual unresolved boundary")
    report = compile_agent_context(memory, max_characters=16000)
    assert report["status"] in {"ok", "partial"}
    assert len(report["context"]) <= 16000
    payload = json.loads(report["context"])
    record = next(row for row in payload["records"] if row["kind"] == "symbol-contract")
    assert {"symbol", "contracts", "invariants", "dependencies", "tests"} <= set(record["value"])
    assert record["value"]["tests"] == ["test_app.py"]
    assert any(row["kind"] == "unknown" for row in payload["records"])
    assert "manual unresolved boundary" in payload["unknowns"]
    assert hashlib.sha256(report["context"].encode()).hexdigest() == report["context_sha256"]


def test_context_budget_cannot_drop_mandatory_unknowns(tmp_path):
    (tmp_path / "app.py").write_text("def f():\n    return 1\n")
    memory = RepositoryMemory(tmp_path)
    memory.refresh()
    memory.limitations.append("x" * 200)
    report = compile_agent_context(memory, max_characters=40)
    assert report["status"] == "unknown" and report["context"] == ""
    assert "context budget cannot retain mandatory UNKNOWN markers" in report["unknowns"]


def test_a2a_success_requires_evidence_and_preserves_budget():
    def handler(params, budget, deadline, cancel):
        return {"status": "completed", "evidence": [{"params": params}], "result": 3}
    result = execute_task(handler, {"x": 1}, budget={"steps": 2}, timeout_ms=1000)
    assert result["status"] == "completed" and result["result"] == 3
    assert result["budget"] == {"steps": 2} and result["evidence"]

    missing = execute_task(lambda *_: {"result": 1}, {})
    assert missing["status"] == "unknown"
    assert "task returned no evidence field" in missing["unknowns"]


def test_a2a_timeout_exposes_late_partial_results_and_execution_state():
    protocol = A2ATaskProtocol()
    started, release = threading.Event(), threading.Event()

    def slow(params, budget, deadline, cancel):
        while time.monotonic() < deadline:
            time.sleep(0.001)
        started.set()
        release.wait(1)
        return {"status": "partial", "partial": True, "evidence": ["partial-work"], "result": {"done": 1}}

    protocol.register("slow", slow)
    submitted = protocol.submit("slow", {}, budget={"steps": 1}, timeout_ms=10)
    task_id = submitted["task_id"]
    assert started.wait(1)
    running = protocol.status(task_id)
    assert running["execution_active"] is True
    release.set()
    final = wait_for(lambda: protocol.status(task_id) if not protocol.status(task_id)["execution_active"] else None)
    assert final["status"] == "timeout" and final["partial"]
    assert final["result"] == {"done": 1} and final["evidence"] == ["partial-work"]


def test_a2a_cooperative_cancellation_and_json_rpc_methods():
    protocol = A2ATaskProtocol()

    def cancellable(params, budget, deadline, cancel):
        while not cancel.is_set() and time.monotonic() < deadline:
            time.sleep(0.005)
        return {"status": "cancelled" if cancel.is_set() else "partial",
                "partial": True, "evidence": ["cancellation observed"]}

    protocol.register("cancellable", cancellable)
    submitted = protocol.handle({"jsonrpc": "2.0", "id": 1, "method": "task.submit", "params": {
        "operation": "cancellable", "input": {}, "budget": {"steps": 1}, "timeout_ms": 1000}})
    task_id = submitted["result"]["task_id"]
    cancelled = protocol.handle({"jsonrpc": "2.0", "id": 2, "method": "task.cancel", "params": {"task_id": task_id}})
    assert cancelled["result"]["status"] in {"cancellation-requested", "cancelled"}
    final = wait_for(lambda: protocol.status(task_id) if not protocol.status(task_id)["execution_active"] else None)
    assert final["status"] == "cancelled" and final["partial"]
    status = protocol.handle({"jsonrpc": "2.0", "id": 3, "method": "task.result", "params": {"task_id": task_id}})
    assert status["result"]["status"] == "cancelled"
    invalid = protocol.handle({"jsonrpc": "2.0", "id": 4, "method": "task.unknown", "params": {}})
    assert invalid["error"]["code"] == -32601


def test_llm_spec_proposals_require_proof_or_confirmed_counterexample():
    proposal = propose_spec("f(x) returns x + 1", metadata={"model": "test"})
    assert proposal["status"] == "conjecture" and proposal["verdict"] == "unknown"
    proved = evaluate_proposal(proposal, lambda _: {"verdict": "proved", "proof": {"certificate": "p"}})
    assert proved["verdict"] == "proved" and proved["unknowns"] == []
    refuted = evaluate_proposal(proposal, lambda _: {
        "verdict": "refuted", "counterexample": {"confirmed": True, "input": 0}})
    assert refuted["verdict"] == "refuted"
    unsupported = evaluate_proposal(proposal, lambda _: {"verdict": "proved"})
    assert unsupported["verdict"] == "unknown"
    failed = evaluate_proposal(proposal, lambda _: (_ for _ in ()).throw(RuntimeError("solver unavailable")))
    assert failed["verdict"] == "unknown" and "solver unavailable" in failed["unknowns"][0]


def test_decision_provenance_explains_allow_deny_default_deny_and_tampering(tmp_path):
    allow = explain_decision({"tool": "shell", "argv": ["git", "status"]}, default_policy(), base_dir=tmp_path)
    assert allow["decision"] == "allowed"
    assert allow["normalized"]["argv"] == ["git", "status"]
    assert any(row["matched"] and row["effect"] == "allow" for row in allow["rules"])

    deny = explain_decision({"tool": "shell", "argv": ["git", "push", "origin", "main"]}, default_policy(), base_dir=tmp_path)
    assert deny["decision"] == "refused" and deny["reason"] == "deny rule #4"
    unknown_tool = explain_decision({"tool": "unknown"}, default_policy(), base_dir=tmp_path)
    assert unknown_tool["decision"] == "refused" and "default-deny" in unknown_tool["reason"]

    path = tmp_path / "decisions.jsonl"
    log = DecisionLog(path)
    log.append({"tool": "shell", "argv": ["git", "status"]}, default_policy(), base_dir=tmp_path)
    log.append({"tool": "unknown"}, default_policy(), base_dir=tmp_path)
    assert log.verify() == {"ok": True, "records": 2, "unknowns": []}
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["reason"] = "tampered"
    lines[0] = json.dumps(first, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    assert not log.verify()["ok"]
