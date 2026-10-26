"""
workflow

║  The pipeline as data (AgentSchema Workflow shape): a named sequence of 
║  steps, each step a {kind: analyze|view|gate|emit} over named engine 
║  components.  run_workflow executes it — the engine describes itself."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Step:
    """Step - see module docstring."""
    name: str
    kind: str            # analyze | opus | gate | emit
    component: str = ""  # analyzer name, opus name, ...
    params: dict = field(default_factory=dict)


@dataclass
class Workflow:
    """Workflow - see module docstring."""
    name: str
    steps: list[Step]

    @staticmethod
    def from_dict(d: dict) -> "Workflow":
        """Implement from dict with the module's explicit API and failure semantics."""
        return Workflow(d["name"], [Step(s["name"], s["kind"], s.get("component", ""),
                                         s.get("params", {})) for s in d["steps"]])

    def to_dict(self) -> dict:
        """Implement to dict with the module's explicit API and failure semantics."""
        return {"name": self.name,
                "steps": [dict({"name": s.name, "kind": s.kind},
                               **({"component": s.component} if s.component else {}),
                               params=s.params) for s in self.steps]}


def run_workflow(source: str, wf: Workflow, out_dir: str = "specs") -> dict:
    """Execute a workflow over `source`.  Steps compose engine components by
    name — no behavior lives here, only sequencing."""
    import pathlib
    state: dict[str, Any] = {}
    for step in wf.steps:
        if step.kind == "analyze":
            from tools.mkspec import core as mkspec_core
            names = [step.component] if step.component else None
            ctx, facts = mkspec_core.run_analyzers(source, names)
            state["ctx"], state["facts"] = ctx, facts
        elif step.kind == "view":
            from tools.mkspec import core as mkspec_core
            names = [step.component] if step.component else None
            state["views"] = mkspec_core.run_opus(state["ctx"], state["facts"], names)
        elif step.kind == "gate":
            from pegrex.contract import validate_contract, manifest_contract
            spec = {"bundle": {"id": pathlib.Path(source).stem, "version": "1.0.0",
                               "effect": "read-write"},
                    "requires": {"engine_version": "1.0.0"},
                    "provides": {"commands": []}}
            state["contract_errors"] = [str(e) for e in
                                        validate_contract(spec, [manifest_contract])]
            if step.params.get("fail_on") and state["contract_errors"]:
                raise RuntimeError(f"gate {step.name}: {state['contract_errors']}")
        elif step.kind == "emit":
            from tools.mkspec import core as mkspec_core
            import json as _json
            spec = mkspec_core.render_spec(state["ctx"], state["facts"],
                                           state.get("views", {}),
                                           step.params.get("template", "full"),
                                           pathlib.Path(source).stem)
            out = pathlib.Path(out_dir)
            out.mkdir(parents=True, exist_ok=True)
            op = out / f"{step.params.get('file', pathlib.Path(source).stem + '.spec.json')}"
            op.write_text(_json.dumps(spec, indent=1), encoding="utf-8")
            state["artifact"] = str(op)
    return state


DEFAULT_AUDIT_WORKFLOW = {
    "name": "audit",
    "steps": [
        {"name": "gather", "kind": "analyze"},
        {"name": "interpret", "kind": "view"},
        {"name": "check-manifest", "kind": "gate", "params": {"fail_on": False}},
        {"name": "write-spec", "kind": "emit", "params": {"template": "full"}},
    ],
}
