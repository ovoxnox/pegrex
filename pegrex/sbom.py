"""Offline CycloneDX 1.5 and SPDX 2.3 SBOM generation from lockfiles."""
from __future__ import annotations
import base64, hashlib, json, re, tomllib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote


def _integrity(value):
    if not value: return []
    try:
        algorithm, encoded = value.split("-", 1)
        name = {"sha1": "SHA-1", "sha256": "SHA-256", "sha512": "SHA-512"}.get(algorithm)
        if not name: return []
        return [{"alg": name, "content": base64.b64decode(encoded).hex()}]
    except (ValueError, TypeError): return []


def _inventory(path):
    path = Path(path); raw = path.read_bytes(); components, edges, unknowns = [], {}, []
    if path.name == "package-lock.json":
        data = json.loads(raw); rows = data.get("packages")
        if not isinstance(rows, dict): raise ValueError("package-lock packages missing")
        names = {}
        for location, meta in sorted(rows.items()):
            if not location: continue
            if "node_modules/" not in location: continue
            name = location.rsplit("node_modules/", 1)[1]
            version = meta.get("version")
            if not version: unknowns.append(f"{name}: version missing"); continue
            names[name] = name
            purl = f"pkg:npm/{quote(name, safe='/')}@{quote(str(version), safe='')}"
            components.append({"name": name, "version": str(version), "ecosystem": "npm",
                "purl": purl, "license": meta.get("license"), "hashes": _integrity(meta.get("integrity")),
                "depends": sorted((meta.get("dependencies") or {}).keys())})
            if not meta.get("integrity"): unknowns.append(f"{name}: integrity hash missing")
    elif path.name == "Cargo.lock":
        data = tomllib.loads(raw.decode())
        for meta in data.get("package", []):
            name, version = meta["name"], meta["version"]
            digest = meta.get("checksum")
            components.append({"name": name, "version": version, "ecosystem": "crates.io",
                "purl": f"pkg:cargo/{quote(name)}@{quote(version)}", "license": None,
                "hashes": [{"alg": "SHA-256", "content": digest}] if digest else [],
                "depends": sorted(str(row).split()[0] for row in meta.get("dependencies", []))})
            if not digest: unknowns.append(f"{name}: checksum missing")
    elif path.name.startswith("requirements") and path.suffix == ".txt":
        for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
            requirement = line.split("#", 1)[0].strip()
            if not requirement:
                continue
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+-]+)", requirement)
            if not match:
                unknowns.append(f"line {number}: unpinned or unsupported requirement")
                continue
            name, version = match.groups()
            canonical = re.sub(r"[-_.]+", "-", name).lower()
            components.append({"name": name, "version": version, "ecosystem": "PyPI",
                "purl": f"pkg:pypi/{quote(canonical)}@{quote(version)}", "license": None,
                "hashes": [], "depends": []})
            unknowns.append(f"{name}: integrity hash missing")
    else:
        raise ValueError("supported SBOM inputs: package-lock.json, Cargo.lock, and pinned requirements*.txt")
    byname = {row["name"]: row for row in components}
    for row in components:
        edges[row["purl"]] = [byname[name]["purl"] for name in row["depends"] if name in byname]
        missing = sorted(set(row["depends"]) - set(byname))
        unknowns.extend(f"{row['name']}: dependency graph target missing: {name}" for name in missing)
    return components, edges, sorted(set(unknowns)), raw


def generate_sbom(lockfile, *, format="cyclonedx", licenses=None) -> dict:
    """Generate one standards-shaped document; unavailable licenses are explicit."""
    components, edges, unknowns, raw = _inventory(lockfile)
    licenses = licenses or {}
    for row in components:
        row["license"] = licenses.get(row["name"], row["license"])
        if not row["license"]: unknowns.append(f"{row['name']}: license NOASSERTION")
    unknowns = sorted(set(unknowns))
    provenance = {"source": str(lockfile), "sha256": hashlib.sha256(raw).hexdigest(),
                  "bytes": len(raw), "generator": "pegrex.sbom", "offline": True}
    if format.lower() in {"cyclonedx", "cdx"}:
        document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"tools": {"components": [{"type": "application", "name": "PegRex", "version": "1.3.0"}]},
                "properties": [{"name": "pegrex:provenance", "value": json.dumps(provenance, sort_keys=True)}] +
                            [{"name": "pegrex:unknown", "value": row} for row in unknowns]},
            "components": [{"type": "library", "bom-ref": row["purl"], "name": row["name"],
                "version": row["version"], "purl": row["purl"], "hashes": row["hashes"],
                **({"licenses": [{"license": {"name": row["license"]}}]} if row["license"] else {})}
                for row in components],
            "dependencies": [{"ref": ref, "dependsOn": deps} for ref, deps in sorted(edges.items())]}
        return document
    if format.lower() == "spdx":
        created = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        identity = hashlib.sha256(json.dumps([components, edges], sort_keys=True).encode()).hexdigest()
        ids = {row["purl"]: f"SPDXRef-Package-{index}" for index, row in enumerate(components)}
        packages = [{"SPDXID": ids[row["purl"]], "name": row["name"], "versionInfo": row["version"],
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": row["license"] or "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": row["purl"]}],
            "checksums": [{"algorithm": row["hashes"][0]["alg"].replace("-", ""),
                           "checksumValue": row["hashes"][0]["content"]}] if row["hashes"] else []}
            for row in components]
        relationships = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                          "relatedSpdxElement": ids[row["purl"]]} for row in components]
        relationships += [{"spdxElementId": ids[ref], "relationshipType": "DEPENDS_ON",
                           "relatedSpdxElement": ids[target]} for ref, deps in sorted(edges.items()) for target in deps]
        return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": Path(lockfile).stem + "-sbom", "documentNamespace": f"urn:pegrex:sbom:{identity}",
            "creationInfo": {"created": created, "creators": ["Tool: PegRex-1.3.0"]},
            "documentComment": json.dumps({"provenance": provenance, "unknowns": unknowns}, sort_keys=True),
            "packages": packages, "relationships": relationships}
    raise ValueError("SBOM format must be cyclonedx or spdx")
