"""Deterministic, budgeted repository context with mandatory UNKNOWN markers."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
SCHEMA="pegrex.agent-context.v1"

def compile_agent_context(memory,*,max_characters=16000) -> dict:
    """Implement compile agent context with the module's explicit API and failure semantics."""
    if memory.memory_identity is None: memory.refresh()
    tests={}
    for path in sorted(Path(memory.root).rglob("test*.py")):
        if any(part in {".git","__pycache__","venv",".venv"} for part in path.parts):continue
        try:text=path.read_text(encoding="utf-8")
        except OSError:continue
        for key,api in memory.apis.items():
            if api["function"] in text:tests.setdefault(key,[]).append(str(path.relative_to(memory.root)))
    records=[]
    for key,api in sorted(memory.apis.items()):
        records.append({"priority":0,"kind":"symbol-contract","id":key,"value":{"symbol":key,"path":api["path"],
            "function_sha256":api["function_sha256"],"contracts":api["contracts"],"status":api["status"],
            "invariants":memory.invariants.get(key,[]),
            "tests":tests.get(key,[]),"dependencies":api["dependencies"]}})
    for row in memory.limitations:records.append({"priority":-1,"kind":"unknown","value":row})
    for path,row in sorted(memory.architecture.items()):records.append({"priority":1,"kind":"architecture","id":path,"value":row})
    mandatory=[row for row in records if row["kind"]=="unknown"]
    optional=sorted((row for row in records if row["kind"]!="unknown"),key=lambda row:(row["priority"],row.get("id","")))
    retained=list(mandatory);dropped=[]
    size=lambda rows:len(json.dumps(rows,sort_keys=True,separators=(",",":"),default=repr))
    if size(retained)>max_characters:
        return {"schema":SCHEMA,"schema_version":1,"status":"unknown","context":"","retained":0,"dropped":len(optional),
                "unknowns":["context budget cannot retain mandatory UNKNOWN markers"]}
    for row in optional:
        if size(retained+[row])<=max_characters:retained.append(row)
        else:dropped.append(row)
    unknowns=list(memory.limitations)
    if dropped:unknowns.append(f"context budget dropped {len(dropped)} lower-priority records")
    payload={"schema":SCHEMA,"schema_version":1,"repository_memory":memory.memory_identity,
             "records":retained,"unknowns":unknowns}
    text=json.dumps(payload,sort_keys=True,separators=(",",":"),default=repr)
    if len(text)>max_characters:
        return {"schema":SCHEMA,"schema_version":1,"status":"unknown","context":"","retained":0,
                "dropped":len(dropped),"unknowns":["context envelope exceeds budget"]}
    return {"schema":SCHEMA,"schema_version":1,"status":"partial" if dropped else "ok",
            "context":text,"context_sha256":hashlib.sha256(text.encode()).hexdigest(),
            "retained":len(retained),"dropped":len(dropped),"unknowns":unknowns}
