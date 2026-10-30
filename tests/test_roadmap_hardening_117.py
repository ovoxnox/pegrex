import hashlib, json, os, subprocess, sys, threading, time
from pathlib import Path
import pytest
from pegrex.requestlimits import validate_request, RequestBudgetError

def test_request_budgets():
    with pytest.raises(RequestBudgetError): validate_request({"x": list(range(2001))})
    with pytest.raises(RequestBudgetError): validate_request({"x": float("nan")})
    nested=0
    for _ in range(34): nested=[nested]
    with pytest.raises(RequestBudgetError): validate_request(nested)

def test_api_error_redaction_and_local_disclosure(monkeypatch,tmp_path):
    from dataclasses import replace
    from pegrex import toolsapi
    old=toolsapi._REGISTRY["core.capabilities"]
    toolsapi._REGISTRY["core.capabilities"]=replace(old,handler=lambda _: (_ for _ in ()).throw(RuntimeError("/srv/private/source.py")))
    try:
        safe=toolsapi.invoke("core.capabilities",{},workspace=tmp_path)
        assert safe["error"]["message"]=="internal operation failure" and "/srv/private" not in json.dumps(safe)
        full=toolsapi.invoke("core.capabilities",{},workspace=tmp_path,disclose_errors=True)
        assert "/srv/private/source.py" in full["error"]["message"]
    finally: toolsapi._REGISTRY["core.capabilities"]=old

def test_workspace_rejects_symlinks_and_escape(tmp_path):
    from pegrex.toolsapi import invoke
    outside=tmp_path.parent/(tmp_path.name+"-outside.py"); outside.write_text("x=1")
    link=tmp_path/"link.py"
    try: link.symlink_to(outside)
    except OSError: pytest.skip("symlinks unavailable")
    assert invoke("core.contracts_file",{"path":"link.py"},workspace=tmp_path)["status"]=="error"
    assert "workspace" in invoke("core.audit",{"path":"../outside.py"},workspace=tmp_path)["error"]["message"]

def test_core_engine_redacts_unexpected_errors(monkeypatch):
    from pegrex.core import CoreEngine
    engine=CoreEngine(); monkeypatch.setattr(engine,"parse",lambda **_: (_ for _ in ()).throw(RuntimeError("/secret")))
    assert "/secret" not in json.dumps(engine.execute("parse",{"source":"x","language":"python"}).to_dict())
    assert "/secret" in json.dumps(engine.execute("parse",{"source":"x","language":"python"},disclose_errors=True).to_dict())

def test_certificate_replay_rejects_unknown_fields_and_checks_source_hashes():
    from pegrex.proofreplay import replay_certificate
    h=hashlib.sha256(b"x").hexdigest()
    cert={"schema":"pegrex.certificate.v1","schema_version":1,"verdict":"proved","claim":"contract-set-identical","unknowns":[],"before_source_sha256":h,"after_source_sha256":h,"evidence":{"before_contracts":[{"constraints":[],"outcome":"x"}],"after_contracts":[{"constraints":[],"outcome":"x"}]}}
    assert replay_certificate(cert)["verdict"]=="unknown"
    assert replay_certificate(cert,before_source="x",after_source="x")["replayed"]
    assert replay_certificate(cert|{"new_critical_field":True})["verdict"]=="unknown"
    assert replay_certificate(cert|{"before_source_sha256":"bad"})["verdict"]=="unknown"

def test_optional_solver_absence_is_explicit(monkeypatch):
    import builtins
    from pegrex import smt
    original=builtins.__import__
    monkeypatch.setattr(builtins,"__import__",lambda name,*a,**kw: (_ for _ in ()).throw(ImportError()) if name=="z3" else original(name,*a,**kw))
    with pytest.raises(smt.SMTCrosscheckError,match="z3 not installed"): smt._z3()

def test_unicode_crlf_and_invalid_encoding(tmp_path):
    from pegrex.core import SourceDocument
    source="# λ\r\ndef café(x):\r\n return x\r\n"; doc=SourceDocument(source,"python"); start=source.index("def café")
    assert doc.slice(start,start+8)=="def café" and doc.line(start)==2
    path=tmp_path/"bad.py"; path.write_bytes(b"\xff")
    with pytest.raises(UnicodeDecodeError): SourceDocument.from_path(path,"python")

def test_optional_parser_absence_is_unknown(monkeypatch):
    from pegrex import languages
    from pegrex.core import CoreEngine
    monkeypatch.setattr(languages,"load_tree_sitter_parser",lambda _: (_ for _ in ()).throw(ImportError("missing")))
    result=CoreEngine().execute("parse",{"source":"package p\nfunc f() {}","language":"go"})
    assert result.status.value=="error" and result.verdict.value=="unknown"

def test_cli_and_tools_api_parse_parity(tmp_path):
    source="def f(x):\n return x+1\n"; root=Path(__file__).resolve().parent.parent; env=dict(os.environ,PYTHONPATH=str(root))
    outputs=[]
    for cmd in ([sys.executable,"-m","pegrex.cli","engine","parse","--input",json.dumps({"source":source,"language":"python"})], [sys.executable,"-m","pegrex.cli","tool","core.parse","--workspace",str(tmp_path),"--input",json.dumps({"source":source,"language":"python"})]):
        proc=subprocess.run(cmd,cwd=root,env=env,capture_output=True,text=True,timeout=30); assert proc.returncode==0,proc.stderr; outputs.append(json.loads(proc.stdout))
    assert outputs[0]["data"]["node_count"]==outputs[1]["data"]["node_count"]
    assert outputs[0]["metadata"]["source_sha256"]==outputs[1]["metadata"]["source_sha256"]

def test_evaluation_metrics_keep_uncovered_unknown():
    from pegrex.evaluation import evaluate_security_predictions
    report=evaluate_security_predictions([{"id":"v","label":"vulnerable","expected_severity":"high"},{"id":"f","label":"fixed"},{"id":"u","label":"vulnerable"}], [{"id":"v","analyzed":True,"finding":True,"severity":"high"},{"id":"f","analyzed":True,"finding":False},{"id":"u","analyzed":False}])
    assert report["verdict"]=="unknown" and report["metrics"]["precision"]==1 and report["metrics"]["coverage"]==pytest.approx(2/3)

def test_a2a_timeout_is_cooperative_not_claimed_as_kill():
    from pegrex.a2atasks import A2ATaskProtocol
    p=A2ATaskProtocol(); started=threading.Event()
    def slow(*args): started.set(); time.sleep(.08); return {"evidence":[],"status":"completed"}
    p.register("slow",slow); submitted=p.submit("slow",{},timeout_ms=10); assert started.wait(1); time.sleep(.025)
    state=p.status(submitted["task_id"]); assert state["execution_active"] and "may still be executing" in state["cancellation"]
