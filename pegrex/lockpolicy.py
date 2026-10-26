"""Lockfile reproducibility and dependency-policy checks without network access."""
from __future__ import annotations
import json, re, tomllib
from pathlib import Path
SCHEMA = "pegrex.lockfile-policy.v1"
_POPULAR = {"requests", "numpy", "django", "flask", "boto3", "cryptography", "urllib3",
            "setuptools", "colorama", "python-dateutil", "lodash", "react", "express",
            "axios", "chalk", "commander", "serde", "tokio", "rand", "regex"}


def _distance(a, b):
    rows = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        following = [i]
        for j, cb in enumerate(b, 1): following.append(min(following[-1] + 1, rows[j] + 1, rows[j-1] + (ca != cb)))
        rows = following
    return rows[-1]


def _name(name): return re.split(r"[<>=!~;\[]", name.strip(), 1)[0].strip().lower()
def _typo(name):
    name = _name(name)
    if name in _POPULAR: return None
    for popular in sorted(_POPULAR):
        if abs(len(name) - len(popular)) <= 1 and _distance(name, popular) == 1: return popular
        if len(name) == len(popular) and any(name[:i] + name[i+1] + name[i] + name[i+2:] == popular for i in range(len(name)-1)): return popular
    return None


def check_lockfile_policy(path, *, require_hashes=False) -> dict:
    """Implement check lockfile policy with the module's explicit API and failure semantics."""
    path = Path(path); violations, signals, unknowns = [], [], []
    def issue(rule, package, evidence, severity="HIGH"):
        """Implement issue with the module's explicit API and failure semantics."""
        violations.append({"rule_id": rule, "package": package, "evidence": evidence, "severity": severity})
    def inspect_name(name):
        """Implement inspect name with the module's explicit API and failure semantics."""
        popular = _typo(name)
        if popular: signals.append({"rule_id": "possible-typosquat", "package": name,
            "evidence": f"similar to popular package {popular}; signal only, not a maliciousness verdict"})
    try:
        if path.name.startswith("requirements") and path.suffix == ".txt":
            for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                line = raw.strip()
                if not line or line.startswith(("#", "--")): continue
                name = _name(line); inspect_name(name)
                if "git+" in line:
                    match = re.search(r"@([0-9a-fA-F]{40})(?:[#&]|$)", line)
                    if not match: issue("unpinned-vcs-reference", name, f"line {number}: VCS reference is not a full commit")
                elif " @ " in line or line.startswith(("http:", "https:", "file:")):
                    if line.startswith("http:") or " @ http:" in line: issue("unsafe-url-dependency", name, f"line {number}: cleartext HTTP")
                    if not require_hashes or "--hash=" not in line: issue("unhashed-url-dependency", name, f"line {number}: URL artifact has no recorded hash")
                elif not re.search(r"(^|\s)(===|==)\s*[A-Za-z0-9.+_-]+\s*$", line):
                    issue("unpinned-dependency", name, f"line {number}: exact ==/=== version required")
                if require_hashes and "--hash=" not in line: issue("missing-artifact-hash", name, f"line {number}: --hash required")
        elif path.name == "package-lock.json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not data.get("lockfileVersion"): unknowns.append("lockfileVersion missing")
            for location, meta in (data.get("packages") or {}).items():
                if not location: continue
                name = location.rsplit("node_modules/", 1)[-1]; inspect_name(name)
                if not meta.get("version") and not meta.get("link"): issue("unlocked-version", name, location)
                resolved = meta.get("resolved", "")
                if resolved.startswith("http:"): issue("unsafe-url-dependency", name, resolved)
                if "git+" in resolved and not re.search(r"#[0-9a-fA-F]{40}$", resolved): issue("unpinned-vcs-reference", name, resolved)
                if not meta.get("integrity") and not meta.get("link"):
                    issue("missing-artifact-hash", name, location, "MEDIUM")
        elif path.name == "Cargo.lock":
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            for meta in data.get("package", []):
                name = meta["name"]; inspect_name(name); source = meta.get("source", "")
                if source.startswith("git+") and not re.search(r"[?&]rev=[0-9a-fA-F]{40}(?:#|$)", source):
                    issue("unpinned-vcs-reference", name, source)
                if source.startswith("registry+") and not meta.get("checksum"):
                    issue("missing-artifact-hash", name, "registry package checksum missing", "MEDIUM")
        else:
            unknowns.append("unsupported lockfile; no policy completeness claimed")
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        unknowns.append(f"lockfile parse failed: {error}")
    verdict = "refuted" if violations else "unknown" if unknowns or signals else "proved"
    return {"schema": SCHEMA, "schema_version": 1, "verdict": verdict,
            "source": {"path": str(path)}, "violations": violations,
            "typosquatting_signals": signals, "unknowns": unknowns,
            "policy": {"exact_versions": True, "https_only": True,
                       "full_vcs_commits": True, "require_hashes": require_hashes}}
