"""LLM spec proposals are conjectures until independently evaluated."""
from __future__ import annotations
import hashlib,json
SCHEMA="pegrex.spec-proposal.v1"

def propose_spec(proposal,*,generator="llm",metadata=None) -> dict:
    """Implement propose spec with the module's explicit API and failure semantics."""
    if not isinstance(proposal,str) or not proposal.strip():raise ValueError("proposal must be nonempty text")
    identity=hashlib.sha256((generator+"\0"+proposal).encode()).hexdigest()
    return {"schema":SCHEMA,"schema_version":1,"identity":identity,"generator":generator,
            "proposal":proposal,"status":"conjecture","verdict":"unknown","evidence":None,
            "metadata":metadata or {},"unknowns":["unevaluated generated proposal"]}

def evaluate_proposal(proposal,checker) -> dict:
    """Implement evaluate proposal with the module's explicit API and failure semantics."""
    if proposal.get("status") not in {"conjecture","evaluated"}:raise ValueError("unsupported proposal")
    result=dict(proposal)
    try:evidence=checker(proposal["proposal"])
    except Exception as error:
        result.update(status="evaluated",verdict="unknown",evidence=None,unknowns=[f"checker error: {error}"]);return result
    verdict=evidence.get("verdict") if isinstance(evidence,dict) else None
    if verdict=="proved" and not evidence.get("proof"):verdict="unknown"
    if verdict=="refuted" and not (evidence.get("counterexample") or {}).get("confirmed"):verdict="unknown"
    if verdict not in {"proved","refuted","unknown"}:verdict="unknown"
    result.update(status="evaluated",verdict=verdict,evidence=evidence,
                  unknowns=[] if verdict!="unknown" else ["proposal was not proved or confirmed-refuted"])
    return result
