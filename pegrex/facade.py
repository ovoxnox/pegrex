"""
facade - the public surface of pegrex in ONE import (audit fix #2).

    from pegrex import facade
    facade.verify_patch(a, b)     # proof or counterexample
    facade.cognitive_complexity(src)
    facade.mine(path) ...

Kept out of api.py deliberately: api is the low-level contract provider and
many modules import it -- re-exporting here would create import cycles.
"""
from .semantics import verify_patch, semantic_diff, contracts_of
from .modernize import modernize
from .tv import wrap, wrap_fn, PROVED, REFUTED, UNKNOWN
from .cognitive import cognitive_complexity
from .cegis import repair
from .chain import repaired_with_evidence
from .bounty import run as bounty_run
from .specmine import mine
from .nlspec import propose as nl_propose, check as nl_check
from .zk import audit_circuit
from .iac import can as iac_can, audit_policy, audit_terraform
from .harness import check_plan, check_action, default_policy
from .compliance import audit_gdpr, audit_soc2
from .mlgraph import check_equivalence
from .vapi import verify_or_refuse, LatencyTracker
from .slsa import attest as slsa_attest, verify as slsa_verify
from .rank import find_ranking
from .emitter import emit_python
from .refine import discharge_source, parse_contracts
from .strategies import strategy, sample_models
from .probpath import fit as probpath_fit, prioritize
from .twin import build as twin_build, ask as twin_ask
from .compress import compress_context, validate_compression


# Stable core entry points. Existing specialized functions above remain available
# as compatibility adapters while consumers migrate to a consistent result model.
from .core import get_engine as engine, OperationResult, OperationStatus, Verdict
from .languages import capability_matrix as language_capabilities
