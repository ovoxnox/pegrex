"""
specs 

║  The schema layer: ProjectSpec (a translation job) and AgentReport 
║  (the AI debugging interface).  Strict JSON, deterministic ordering."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field


class PreprocessSpec(BaseModel):
    """PreprocessSpec - see module docstring."""
    language: str  # python | go | rust | lua | c
    entrypoints: list[str] = []
    build_commands: list[str] = []
    include_paths: list[str] = []
    defines: dict[str, str] = {}
    preprocess_source: bool = False
    tree_sitter_grammar: str | None = None


class PostprocessSpec(BaseModel):
    """PostprocessSpec - see module docstring."""
    expected_artifacts: list[str] = []
    test_commands: list[str] = []
    invariants: list[str] = []
    preserve_ids: list[str] = []


class IdiomRule(BaseModel):
    """IdiomRule - see module docstring."""
    name: str
    source_tags: list[str]
    target_template: str
    path_guard: str | None = None


class ProjectSpec(BaseModel):
    """A complete translation/verification job: input + acceptance criteria."""
    name: str
    preprocess: PreprocessSpec
    postprocess: PostprocessSpec = Field(default_factory=PostprocessSpec)
    idiom_rules: list[IdiomRule] = []

    def schema_json(self, **kw) -> str:
        """schema json(): see module docstring."""
        return json.dumps(self.model_json_schema(), indent=2)


class Violation(BaseModel):
    """Violation - see module docstring."""
    rule_id: str
    node_type: str
    position: dict | None = None
    detail: str = ""
    severity: str = "warning"


class PathReport(BaseModel):
    """PathReport - see module docstring."""
    path_id: int
    blocks: list[int]
    constraints: list[str]
    satisfiable: bool
    result: str | None = None
    ssa_versions: dict[str, str] = {}


class State(BaseModel):
    id: int
    term: str = "fall"  # fall | branch | loopcond | ret


class Transition(BaseModel):
    """Transition - see module docstring."""
    src: int
    dst: int
    guard: str | None = None    # path-constraint text (policy-IR: guards)


class AgentReport(BaseModel):
    """Machine-readable spec for AI agents — prompt context, not prose.

    policy-IR additions: the function's CFG as an explicit state machine
    (states/transitions) + assertions as first-class constraint citizens.

    Ingest via .to_agent_json(); diff across TDD iterations; stop when
    violations == [] and every path is satisfiable."""
    language: str
    entrypoint: str
    preprocess: PreprocessSpec
    syntactic_violations: list[Violation] = []
    ssa_phi_nodes: list[dict] = []
    states: list[State] = []
    transitions: list[Transition] = []
    assertions: list[str] = []
    paths: list[PathReport] = []
    z3: dict = {}
    postprocess: PostprocessSpec = Field(default_factory=PostprocessSpec)

    def to_agent_json(self) -> str:
        """Implement to agent json with the module's explicit API and failure semantics."""
        return json.dumps(self.model_dump(), indent=1, sort_keys=True)


class Policy(BaseModel):
    """allowed/forbidden operations for the agent (AgentSchema naming)."""
    allowed: list[str] = []
    forbidden: list[str] = []


class AgentManifest(BaseModel):
    """Deployment record: what THIS analysis run provided (AgentSchema split:
    AgentReport = what the code IS; AgentManifest = what ran on it)."""
    definition: str = ""  # name of the AgentReport this deploys
    engine_version: str = "1.0.0"
    analyzers: list[str] = []
    opus: list[str] = []
    rule_packs: list[str] = []
    policy: Policy = Field(default_factory=Policy)
    created_at: str = ""

    def to_agent_json(self) -> str:
        """Implement to agent json with the module's explicit API and failure semantics."""
        return json.dumps(self.model_dump(), indent=1, sort_keys=True)
