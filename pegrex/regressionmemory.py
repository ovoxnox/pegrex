"""Persistent fixed-finding regressions and rule-negative controls."""
from __future__ import annotations
import hashlib,json,os
from pathlib import Path
SCHEMA="pegrex.security-regression-memory.v1"

def _scan(source,rule):
    from .flow import analyze_source
    return any(row.get("id")==rule for row in analyze_source(source)["findings"])

def register_finding_fix(finding,vulnerable_source,fixed_source,test_path,memory_path) -> dict:
    """Refuse registration unless the rule fires before and stays absent after."""
    rule=finding.get("id")
    if not rule: return {"schema":SCHEMA,"status":"unknown","unknowns":["stable finding id required"]}
    if not _scan(vulnerable_source,rule):
        return {"schema":SCHEMA,"status":"unknown","unknowns":["rule-negative control does not reproduce the original finding"]}
    if _scan(fixed_source,rule):
        return {"schema":SCHEMA,"status":"refuted","unknowns":["fixed source still triggers the finding"]}
    test_path=Path(test_path);test_path.parent.mkdir(parents=True,exist_ok=True)
    identity=hashlib.sha256((rule+"\0"+vulnerable_source+"\0"+fixed_source).encode()).hexdigest()
    test=f"""# Generated PegRex security regression {identity}.
from pegrex.flow import analyze_source
RULE_ID = {rule!r}
VULNERABLE = {vulnerable_source!r}
FIXED = {fixed_source!r}
def findings(source):
    return analyze_source(source)["findings"]
def test_fixed_finding_{identity[:12]}():
    assert RULE_ID not in {{row["id"] for row in findings(FIXED)}}
def test_rule_negative_control_{identity[:12]}():
    assert RULE_ID in {{row["id"] for row in findings(VULNERABLE)}}
"""
    test_path.write_text(test, encoding="utf-8")
    memory_path=Path(memory_path);memory_path.parent.mkdir(parents=True,exist_ok=True)
    try: document=json.loads(memory_path.read_text(encoding="utf-8"))
    except (OSError,ValueError): document={"schema":SCHEMA,"schema_version":1,"entries":[]}
    row={"identity":identity,"finding":finding,"vulnerable_sha256":hashlib.sha256(vulnerable_source.encode()).hexdigest(),
         "fixed_sha256":hashlib.sha256(fixed_source.encode()).hexdigest(),"test_path":str(test_path),
         "test_sha256":hashlib.sha256(test.encode()).hexdigest(),"negative_control":"original vulnerable source must trigger rule"}
    if not any(row["identity"]==entry["identity"] for entry in document["entries"]): document["entries"].append(row)
    document["entries"].sort(key=lambda row:row["identity"])
    temporary=memory_path.with_suffix(memory_path.suffix+".tmp");temporary.write_text(json.dumps(document,sort_keys=True,indent=2)+"\n", encoding="utf-8");os.replace(temporary,memory_path)
    return {"schema":SCHEMA,"status":"registered","entry":row,"unknowns":[]}

def verify_regression_memory(memory_path) -> dict:
    """Implement verify regression memory with the module's explicit API and failure semantics."""
    try: document=json.loads(Path(memory_path).read_text(encoding="utf-8"))
    except (OSError,ValueError) as error:return {"schema":SCHEMA,"status":"unknown","unknowns":[str(error)]}
    unknowns=[]
    for row in document.get("entries",[]):
        try:
            if hashlib.sha256(Path(row["test_path"]).read_bytes()).hexdigest()!=row["test_sha256"]:unknowns.append("test artifact changed: "+row["identity"])
        except OSError as error:unknowns.append(str(error))
    return {"schema":SCHEMA,"status":"ok" if not unknowns else "unknown","entries":len(document.get("entries",[])),"unknowns":unknowns}
