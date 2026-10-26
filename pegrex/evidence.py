"""
evidence - deterministic replay + evidence bundles

An evidence bundle freezes an analysis run so anyone holding the HMAC key can
answer three questions offline:

  pack()    run the analyzer fresh, fingerprint everything with xxh64,
            HMAC-sign the manifest (pegrex.attest -- the one HMAC copy)
  verify()  bundle integrity: signature + every bundled artifact hash.
            Tampering is named ("tampered:contracts", "tampered:witness:x");
            a legitimate SOURCE edit since packing is NOT a verify failure --
            that is what replay measures (drift is not tampering)
  replay()  verify() first, then re-run the analyzer on the current source
            and compare path count / constraint sets / results. stable=False
            is an honest "the source moved" verdict, never an error; a
            signature failure or tampering IS an error verdict (ok=False)

xxhash is an optional dependency on purpose: without it the module refuses
at call time, loudly -- it never falls back to a silently weaker fingerprint."""

from __future__ import annotations

try:
    import xxhash
except ImportError: # refused loudly at call time
    xxhash = None

import json
import pathlib
from datetime import datetime, timezone

from .attest import canonical_json, hmac_sign, hmac_verify


class EvidenceError(ValueError):
    pass


def _require_xxhash():
    if xxhash is None:
        raise EvidenceError(
            "evidence: xxhash required -- pip install pegrex[evidence] / "
            "xxhash required; refusing to fingerprint evidence with a "
            "non-cryptographic stand-in silently")


def _xxh64(data: bytes) -> str:
    _require_xxhash()
    return xxhash.xxh64(data).hexdigest()


def _engine_version() -> str:
    try:
        import importlib.metadata
        return importlib.metadata.version("pegrex")
    except Exception:
        return "dev"


def _run_analyzer(analyzer: str, source_path):
    """Fresh analyzer run. 'api.contracts' (default) or 'pkg.mod:callable'."""
    if analyzer == "api.contracts":
        from . import api
        fn = api.contracts
    elif ":" in analyzer:
        import importlib
        mod, _, attr = analyzer.partition(":")
        try:
            fn = getattr(importlib.import_module(mod), attr)
        except Exception as e:
            raise EvidenceError(
                f"evidence: analyzer {analyzer!r} unavailable: {e!r}")
    else:
        raise EvidenceError(
            f"evidence: unknown analyzer {analyzer!r} "
            "(use 'api.contracts' or 'pkg.mod:callable')")
    try:
        return fn(str(source_path))
    except EvidenceError:
        raise
    except Exception as e:
        raise EvidenceError(f"evidence: analyzer {analyzer} refused: {e!r}")


def _rows_to_json(rows) -> list:
    return [{"constraints": sorted(map(str, cs)), "result": str(res)}
            for cs, res in rows]


def pack(source_path, out_dir, key, config=None, witnesses=None,
         analyzer="api.contracts") -> pathlib.Path:
    """Analyze fresh, fingerprint, sign, and write the bundle to out_dir.

    Layout: manifest.json ({"manifest": ..., "signature": ...}),
    contracts.json, witnesses/<name>. Returns out_dir."""
    _require_xxhash()
    sp = pathlib.Path(source_path)
    if not sp.exists():
        raise EvidenceError(f"evidence: source does not exist: {source_path}")
    rows = _run_analyzer(analyzer, sp)
    contracts = _rows_to_json(rows)
    contracts_bytes = canonical_json(contracts).encode()

    out = pathlib.Path(out_dir)
    (out / "witnesses").mkdir(parents=True, exist_ok=True)
    wmap = {}
    for name, text in (witnesses or {}).items():
        if not isinstance(text, str):
            raise EvidenceError(
                f"evidence: witness {name!r} must be text (str), got "
                f"{type(text).__name__}")
        safe = name.replace("/", "_").replace("..", "_")
        wb = text.encode()
        (out / "witnesses" / safe).write_bytes(wb)
        wmap[name] = {"text": text, "xxh64": _xxh64(wb),
                      "file": f"witnesses/{safe}"}

    manifest = {
        "engine": {"name": "pegrex", "version": _engine_version()},
        "analyzer": analyzer,
        "source_path": str(sp.resolve()),
        "source_xxh64": _xxh64(sp.read_bytes()),
        "contracts_xxh64": _xxh64(contracts_bytes),
        "witnesses": wmap,
        "config": config or {},
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    (out / "contracts.json").write_bytes(contracts_bytes)
    signed = {"manifest": manifest, "signature": hmac_sign(manifest, key)}
    (out / "manifest.json").write_text(
        json.dumps(signed, indent=1, sort_keys=True), encoding="utf-8")
    return out


def verify(bundle_dir, key) -> dict:
    """Bundle integrity: HMAC signature + every bundled artifact hash.
    Names the tampered artifact. Source drift since packing is replay's
    honest verdict, not a verify failure."""
    _require_xxhash()
    bd = pathlib.Path(bundle_dir)
    try:
        mf = json.loads((bd / "manifest.json").read_text(encoding="utf-8"))
    except Exception as e:
        return {"ok": False, "reason": f"unreadable bundle: {e!r}"}
    m, sig = mf.get("manifest"), mf.get("signature")
    if not isinstance(m, dict) or not sig:
        return {"ok": False,
                "reason": "incomplete bundle: manifest/signature missing"}
    if not hmac_verify(m, key, sig):
        return {"ok": False, "reason": "signature mismatch"}
    cp = bd / "contracts.json"
    if not cp.exists() or _xxh64(cp.read_bytes()) != m.get("contracts_xxh64"):
        return {"ok": False, "reason": "tampered:contracts"}
    n = 1
    for name, w in (m.get("witnesses") or {}).items():
        wp = bd / w.get("file", "")
        if not wp.is_file() or _xxh64(wp.read_bytes()) != w.get("xxh64"):
            return {"ok": False, "reason": f"tampered:witness:{name}"}
        n += 1
    return {"ok": True, "artifacts": n}


def replay(bundle_dir, key) -> dict:
    """verify() first; then re-run the analyzer on the CURRENT source and
    compare path count, constraint sets, and results per path. stable=False
    (source legitimately changed) is an honest verdict with the diff listed;
    tampering or a bad key is an error verdict (ok=False)."""
    v = verify(bundle_dir, key)
    if not v["ok"]:
        return {"ok": False, "reason": v["reason"]}
    bd = pathlib.Path(bundle_dir)
    m = json.loads((bd / "manifest.json").read_text(encoding="utf-8"))["manifest"]
    sp = pathlib.Path(m["source_path"])
    if not sp.exists():
        return {"ok": False, "reason": f"source missing: {sp}"}
    old = json.loads((bd / "contracts.json").read_text(encoding="utf-8"))
    new = _rows_to_json(_run_analyzer(m["analyzer"], sp))
    diff = []
    if len(old) != len(new):
        diff.append({"kind": "path-count", "before": len(old),
                     "after": len(new)})
    for i, (o, n) in enumerate(zip(old, new)):
        if o["constraints"] != n["constraints"]:
            diff.append({"kind": "constraints", "path": i,
                         "before": o["constraints"],
                         "after": n["constraints"]})
        elif o["result"] != n["result"]:
            diff.append({"kind": "result", "path": i,
                         "before": o["result"], "after": n["result"]})
    return {"ok": True, "stable": not diff, "diff": diff}
