"""
sca -- dependency vulnerability scanning (OSV.dev) 

║  Inventory -> OSV API match -> findings, with a local cache for  
║  performance and offline operation."""

from __future__ import annotations

import json
import hashlib
import json
import pathlib
import urllib.request

CACHE = pathlib.Path(".pegrex-cache/osv.json")


def _cache():
    if CACHE.exists():
        return json.loads(CACHE.read_text())
    return {}


def inventory_from(path: str) -> list:
    """{name, version, ecosystem} from go.mod / Cargo.lock / package-lock.json."""
    import re
    import json as _json
    p = pathlib.Path(path)
    out = []
    if p.name == "go.mod":
        for ln in p.read_text().splitlines():
            m = re.match(r"^\s*(?:require\s+)?([\w.~/-]+)\s+v([\w.+-]+)", ln)
            if m and not ln.strip().startswith(("module", "go ")):
                out.append({"name": m.group(1), "version": m.group(2),
                            "ecosystem": "Go"})
    elif p.name == "Cargo.lock":
        for m in re.finditer(r'name = "([\w-]+)"\nversion = "([\w.+-]+)"',
                             p.read_text()):
            out.append({"name": m.group(1), "version": m.group(2),
                        "ecosystem": "crates.io"})
    elif p.name == "package-lock.json":
        data = _json.loads(p.read_text())
        for name, meta in (data.get("packages") or {}).items():
            if name.startswith("node_modules/"):
                out.append({"name": name[13:], "version": meta.get("version"),
                            "ecosystem": "npm"})
    return out


def osv_query(dep: dict, timeout: int = 15) -> list:
    """One OSV query (cached). Returns vulnerability list (may be [] offline)."""
    cache = _cache()
    key = hashlib.sha256(json.dumps(dep).encode()).hexdigest()[:16]
    if key in cache:
        return cache[key]
    vulns = []
    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps({"package": {"name": dep["name"],
                                         "ecosystem": dep["ecosystem"]},
                             "version": dep["version"]}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read())
        vulns = [{"id": v["id"],
                  "summary": v.get("summary", "")[:120]}
                 for v in data.get("vulns", [])]
    except Exception:
        pass  # offline: inventory only
    cache[key] = vulns
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(cache))
    return vulns


def scan(path: str) -> dict:
    """lockfile -> {dependencies, vulnerabilities, offline-aware}."""
    deps = inventory_from(path)
    vulns = []
    for d in deps:
        for v in osv_query(d):
            vulns.append({**d, **v})
    return {"dependencies": len(deps), "vulnerabilities": vulns,
            "offline": not vulns and bool(deps)}
