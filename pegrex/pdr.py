"""
pdr — property-directed checking, PDR-lite slice

║  NOT full IC3/PDR: there is a single Houdini-inferred fixpoint, not a   
║  sequence of frames, and no counterexample-to-induction/propagation.    
║  That one fixpoint stands in for a frame: initiation + consecution
║  discharged by the engine. A safety property P is then checked:     
║    proven      -- fixpoint + guard |= P (certificate: the invariants)   
║    violated    -- fixpoint + guard |= ~P, with a concrete witness       
║    unknown     -- neither discharges: reported, never assumed"""

from __future__ import annotations

from .invariants import infer_invariants
from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of
from .refine import _neg

DEFAULT_LB = LinearBackend()


def check_property(guard_text, deltas, init_atoms, prop_text, lb=None,
                   rounds=6) -> dict:
    """Check P over the loop. Returns verdict + witnesses/certificates."""
    lb = lb or DEFAULT_LB
    inv = infer_invariants(guard_text, deltas, init_atoms, lb, rounds)
    inv_atoms = []
    for c in inv["invariants"]:
        try:
            inv_atoms += atoms_of(lower_condition(c))
        except Exception:
            pass
    guard_atoms = atoms_of(lower_condition(guard_text))

    def model_of(extra):
        """Implement model of with the module's explicit API and failure semantics."""
        return lb.learn(inv_atoms + guard_atoms + extra)

    prop = lower_condition(prop_text)
    neg = _neg(prop)

    # violated anywhere reachable?
    m_neg = model_of([a for a in atoms_of(neg)])
    if m_neg.feasible():
        vals = m_neg.model()
        if vals and not lb.entails(m_neg, prop):
            # violation proven if frame+guard |= ~P on the whole region:
            whole = lb.learn(inv_atoms + guard_atoms)
            if lb.entails(whole, neg):
                return {"status": "violated", "witness": vals,
                        "invariants": inv["invariants"]}
    # proven?
    whole = lb.learn(inv_atoms + guard_atoms)
    try:
        if lb.entails(whole, prop):
            return {"status": "proven",
                    "certificate": {"invariants": inv["invariants"],
                                    "guard": guard_text, "property": prop_text}}
    except Exception:
        pass
    return {"status": "unknown", "invariants": inv["invariants"]}
