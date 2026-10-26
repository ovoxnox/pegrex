"""Hash-chained provenance for agent-plan allow/refuse decisions."""
from __future__ import annotations
import hashlib,json,os
from pathlib import Path
from .harness import check_action,_rule_matches
SCHEMA="pegrex.decision-provenance.v1"

def explain_decision(action,policy,*,base_dir=None) -> dict:
    """Implement explain decision with the module's explicit API and failure semantics."""
    decision=check_action(action,policy,base_dir=base_dir);rules=[]
    for index,rule in enumerate(policy):
        args=action.get("args","");argv=action.get("argv") if action.get("tool")=="shell" else None
        try:matched=_rule_matches(rule,action.get("tool",""),args,action.get("path",""),argv)
        except Exception:matched=False
        rules.append({"index":index,"effect":rule.get("effect"),"constraints":{k:v for k,v in rule.items() if k!="effect"},"matched":matched})
    reason=decision.get("reason")
    if decision["verdict"]=="allowed":reason="allow rule #"+str(decision.get("rule"))+" matched"
    return {"schema":SCHEMA,"schema_version":1,"action":action,"decision":decision["verdict"],
            "reason":reason,"normalized":{"argv":decision.get("argv"),"path":decision.get("path")},"rules":rules}

class DecisionLog:
    def __init__(self,path):self.path=Path(path)
    def append(self,action,policy,*,base_dir=None) -> dict:
        """Implement append with the module's explicit API and failure semantics."""
        previous="0"*64
        if self.path.exists():
            lines=self.path.read_text(encoding="utf-8").splitlines()
            if lines:previous=json.loads(lines[-1])["record_sha256"]
        record=explain_decision(action,policy,base_dir=base_dir);record["previous_sha256"]=previous
        record["record_sha256"]=hashlib.sha256(json.dumps(record,sort_keys=True,separators=(",",":")).encode()).hexdigest()
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
        return record
    def verify(self) -> dict:
        """Implement verify with the module's explicit API and failure semantics."""
        previous="0"*64;count=0;unknowns=[]
        try:lines=self.path.read_text(encoding="utf-8").splitlines()
        except OSError as error:return {"ok":False,"unknowns":[str(error)]}
        for line in lines:
            try:
                record=json.loads(line);claimed=record.pop("record_sha256")
                actual=hashlib.sha256(json.dumps(record,sort_keys=True,separators=(",",":")).encode()).hexdigest()
                if record.get("previous_sha256")!=previous or claimed!=actual:unknowns.append("decision log chain mismatch")
                previous=claimed;count+=1
            except (ValueError,KeyError) as error:unknowns.append(str(error))
        return {"ok":not unknowns,"records":count,"unknowns":unknowns}
