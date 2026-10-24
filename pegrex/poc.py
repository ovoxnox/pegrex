"""poc.py -- bug-bounty copilot: a taint path becomes a PoC request template.
The agent fills the payload; the engine certifies reachability."""
from __future__ import annotations


def poc_template(finding: dict) -> str:
    """Render a finding as a ready-to-send HTTP PoC template."""
    return (f"# PoC for {finding['id']} (L{finding.get('line', '?')})\n"
            f"# evidence: {finding.get('evidence', '')[:80]}\n"
            f"GET /?cmd=<PAYLOAD> HTTP/1.1\n"
            f"Host: target\n\n"
            f"# verify: response reflects injected command output")


def codegen_gate(snippet: str, max_findings: int = 0) -> dict:
    """AI-codegen verification at generation time: audit before the snippet
    reaches the editor.  Returns {accepted, findings}."""
    import pathlib, tempfile
    import sys
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from tools.secaudit import audit
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(snippet)
        tmp = f.name
    findings = audit(tmp)
    return {"accepted": len(findings) <= max_findings, "findings": findings}
