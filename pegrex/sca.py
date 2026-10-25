"""
sca -- dependency vulnerability scanning (OSV.dev)

Inventory -> OSV API match -> findings, with a content-addressed local cache.
Reproducible scans use an explicit local snapshot and ``offline=True``. Missing
snapshot/cache entries are UNKNOWN, never zero vulnerabilities.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import urllib.request

CACHE = pathlib.Path(".pegrex-cache/osv.json")
SNAPSHOT_SCHEMA = "pegrex.osv-snapshot.v1"


class OSVDataUnavailable(RuntimeError):
    """No authoritative vulnerability answer is available for a dependency."""


def _dependency_key(dep: dict) -> str:
    canonical = json.dumps(dep, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _cache(path=None) -> dict:
    path = pathlib.Path(path) if path else CACHE
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise OSVDataUnavailable(f"invalid OSV cache {path}: {exc}") from exc
    return data.get("queries", data) if isinstance(data, dict) else {}


def _write_json(path: pathlib.Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    temporary.replace(path)


def snapshot_provenance(path=None) -> dict:
    if path is None:
        return {"mode": "online", "id": "live-api",
                "endpoint": "https://api.osv.dev/v1/query", "reproducible": False}
    path = pathlib.Path(path)
    raw = path.read_bytes()
    document = json.loads(raw)
    metadata = document.get("metadata", {}) if isinstance(document, dict) else {}
    snapshot_id = (document.get("snapshot") if isinstance(document, dict) else None)
    snapshot_id = snapshot_id or metadata.get("snapshot") or metadata.get("id")
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "mode": "offline", "id": snapshot_id or "sha256:" + digest,
        "sha256": digest, "path": str(path), "reproducible": True,
    }


def _snapshot_document(path) -> dict:
    document = json.loads(pathlib.Path(path).read_text())
    if not isinstance(document, dict):
        raise OSVDataUnavailable("OSV snapshot must be a JSON object")
    return document


def _vulnerability_list(record, context: str) -> list:
    if isinstance(record, dict) and "vulnerabilities" in record:
        record = record["vulnerabilities"]
    if (not isinstance(record, list)
            or any(not isinstance(item, dict) or not item.get("id") for item in record)):
        raise OSVDataUnavailable(f"invalid OSV vulnerability entry: {context}")
    return record


def _snapshot_vulns(document: dict, dep: dict, key: str) -> list:
    queries = document.get("queries", document)
    alternate = f"{dep['ecosystem']}:{dep['name']}:{dep['version']}"
    if key not in queries and alternate not in queries:
        raise OSVDataUnavailable(
            f"dependency absent from offline OSV snapshot: {alternate}")
    record = queries.get(key, queries.get(alternate))
    return _vulnerability_list(record, alternate)


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


def osv_query(dep: dict, timeout: int = 15, *, offline: bool = False,
              snapshot=None, cache_path=None) -> list:
    """One OSV query with explicit provenance and no silent offline fallback."""
    key = _dependency_key(dep)
    if snapshot is not None:
        return _snapshot_vulns(_snapshot_document(snapshot), dep, key)
    cache_file = pathlib.Path(cache_path) if cache_path else CACHE
    cache = _cache(cache_file)
    if key in cache:
        return _vulnerability_list(cache[key], f"cache key {key}")
    if offline:
        raise OSVDataUnavailable(
            f"dependency absent from offline OSV cache: "
            f"{dep['ecosystem']}:{dep['name']}:{dep['version']}")

    request = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps({"package": {"name": dep["name"],
                                     "ecosystem": dep["ecosystem"]},
                         "version": dep["version"]}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read())
    except Exception as exc:
        raise OSVDataUnavailable(f"OSV query failed: {type(exc).__name__}: {exc}") from exc
    vulns = [{"id": vulnerability["id"],
              "summary": vulnerability.get("summary", "")[:120]}
             for vulnerability in data.get("vulns", [])]
    cache[key] = vulns
    _write_json(cache_file, cache)
    return vulns


def scan(path: str, *, offline: bool = False, snapshot=None,
         cache_path=None, snapshot_out=None) -> dict:
    """Lockfile -> vulnerabilities + explicit status and reproducibility data."""
    source = pathlib.Path(path)
    source_bytes = source.read_bytes()
    deps = inventory_from(path)
    offline = offline or snapshot is not None
    cache_file = pathlib.Path(cache_path) if cache_path else CACHE
    provenance_path = snapshot or (cache_file if offline and cache_file.exists() else None)
    if offline and provenance_path is None:
        osv_provenance = {"mode": "offline", "id": "unavailable",
                          "reproducible": False}
    else:
        osv_provenance = snapshot_provenance(provenance_path)
        osv_provenance["mode"] = "offline" if offline else "online"
    vulns, unknowns, captured = [], [], {}
    for dependency in deps:
        key = _dependency_key(dependency)
        try:
            matches = osv_query(dependency, offline=offline, snapshot=snapshot,
                                cache_path=cache_file)
        except (OSVDataUnavailable, OSError, json.JSONDecodeError) as exc:
            unknowns.append({"dependency": dependency, "reason": str(exc)[:500]})
            continue
        captured[key] = {"dependency": dependency, "vulnerabilities": matches}
        for vulnerability in matches:
            vulns.append({**dependency, **vulnerability})

    if snapshot_out is not None:
        if unknowns:
            raise OSVDataUnavailable(
                "refusing to write an incomplete OSV snapshot: "
                + unknowns[0]["reason"])
        output = pathlib.Path(snapshot_out)
        payload = json.dumps(captured, sort_keys=True, separators=(",", ":"))
        document = {
            "schema": SNAPSHOT_SCHEMA,
            "snapshot": "osv-query-sha256:" + hashlib.sha256(payload.encode()).hexdigest(),
            "source": "https://api.osv.dev/v1/query",
            "queries": captured,
        }
        _write_json(output, document)
        osv_provenance = snapshot_provenance(output)
        osv_provenance["mode"] = "offline" if offline else "online-captured"

    status = "unknown" if unknowns else "complete"
    osv_provenance["status"] = status
    return {
        "schema": "pegrex.osv-scan.v1",
        "dependencies": len(deps), "vulnerabilities": vulns,
        "offline": offline, "status": status, "unknowns": unknowns,
        "provenance": {
            "schema": "pegrex.osv-provenance.v1",
            "source": {"path": str(path),
                       "sha256": hashlib.sha256(source_bytes).hexdigest(),
                       "bytes": len(source_bytes)},
            "osv": osv_provenance,
        },
    }
