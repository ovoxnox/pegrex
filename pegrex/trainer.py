"""
trainer — verified-pair training-data exporter 

║  (edit, certificate) pairs make a clean fine-tuning dataset with proof  
║  signal. Only verified pairs are exported; refused pairs are excluded   
║  and counted. The exporter never ships an unverified claim."""

from __future__ import annotations

import json

from .benchmark import CASES, run_case


def export_pairs(path, cases=None):
    """Write JSONL of verified pairs only. Returns counts."""
    cases = cases if cases is not None else CASES
    verified = excluded = 0
    with open(path, "w", encoding="utf-8") as f:
        for case in cases:
            r = run_case(case)
            if r["verified"] is True and r["expected"]:
                f.write(json.dumps({
                    "before": case["before"],
                    "after": case["after"],
                    "task": case["name"],
                    "certificate": {"verified": True, "claim": "equivalent",
                                    "engine": "pegrex.verify_patch"},
                }) + "\n")
                verified += 1
            else:
                excluded += 1
    return {"exported": verified, "excluded": excluded}


def load_pairs(path):
    """Implement load pairs with the module's explicit API and failure semantics."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]
