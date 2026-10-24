"""
invmarket — the invariant stock exchange 

║  Publish, price, import and discharge obligations with market-proven    
║  invariants, on top of registry.py's signed-manifest machinery.         

║  listing rule: an invariant is published only after the engine has      
║  proved it against the package's current files (every path entails it,  
║  result substituted per path, via the entailment engine) -- an     
║  unprovable invariant is a loud InvMarketError naming the atom, never   
║  a listing. Every entry is HMAC-signed (pegrex.attest) and hash-        
║  chained into an append-only book inside the registry file; import      
║  re-verifies signatures AND the chain, and a tampered entry is a loud   
║  refusal naming the package and entry -- record-and-refuse, because     
║  trading on a tampered book is worse than refusing to trade.            
║  Import is NOT re-proof: freshness is a discharge-time entailment,      
║  never implied (see claims())."""

from __future__ import annotations

import hashlib
import os
import pathlib
import re
import tempfile

from .attest import canonical_json, hmac_sign, hmac_verify
from .linsolve import LinearBackend, LinearError, parse_atom
from .refine import _norm_constraint
from .registry import load_registry, save_registry

DEFAULT_KEY = "invmarket-demo-key"
MARKET_SECTION = "market"          # top-level section inside the registry file


class InvMarketError(ValueError):
    """Loud refusal from the invariant market -- never a silent trade."""


# packages: the "current files" an invariant must be proven against

def _package_files(registry_path, package):
    """Resolve `package` to (name, {filename: source}).

    Accepted forms, stated loudly:
      * str  -- a package name; current files are every *.py under
                ``pathlib.Path(registry_path).parent / package`` (missing
                directory or no .py files is a loud refusal).
      * dict -- {logical_filename: source}; an optional "__name__" key names
                the package (default "<unnamed-package>").
    """
    if isinstance(package, dict):
        files = {k: v for k, v in package.items() if k != "__name__"}
        name = package.get("__name__", "<unnamed-package>")
        if not files:
            raise InvMarketError(
                f"invmarket: package {name!r} carries no source files -- "
                f"there is nothing to prove an invariant against")
        return name, files
    if isinstance(package, str):
        root = pathlib.Path(registry_path).parent / package
        if not root.is_dir():
            raise InvMarketError(
                f"invmarket: package {package!r} has no source directory at "
                f"{root} -- refusing to list an invariant against files "
                f"that cannot be found")
        files = {str(p.relative_to(root)): p.read_text()
                 for p in sorted(root.rglob("*.py"))}
        if not files:
            raise InvMarketError(
                f"invmarket: package {package!r} has no .py files under "
                f"{root} -- refusing to list an invariant against nothing")
        return package, files
    raise InvMarketError(
        f"invmarket: package must be a name (str) or a {{file: source}} "
        f"dict, got {type(package).__name__}")


def _normalize_atom_text(atom: str) -> str:
    """Atom text -> normalized solver atom text via the IR. Raises
    LinearError outside the linear fragment (var-vs-var comparisons like
    'result >= n' normalize fine; 'n*n >= 0' refuses loudly)."""
    from .ir import cond_to_atom, lower_condition
    norm = cond_to_atom(lower_condition(str(atom).strip()))
    parse_atom(norm)
    return norm


def _path_atoms(constraint_strs):
    """Parseable linear atoms for one path; opaque constraints dropped
    (the safe direction: less information, never a false proof)."""
    atoms = []
    for c in constraint_strs:
        n = _norm_constraint(str(c))
        try:
            parse_atom(n)
            atoms.append(n)
        except Exception:
            pass
    return atoms


def _atom_provable(files, atom, lb):
    """True iff some file proves `atom`: every path's constraints entail
    it (with `result` substituted per path). A path that falls entirely
    outside the linear fragment cannot entail anything -- the atom is not
    provable via that file (mirrors specmine's discipline)."""
    from . import api
    for fname, src in sorted(files.items()):
        fd, path = tempfile.mkstemp(suffix=".py")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(src)
            contracts = api.contracts(path)
        finally:
            os.unlink(path)
        saw_path = False
        proven_here = True
        for cs, res in contracts:
            saw_path = True
            atoms = _path_atoms(cs)
            if not atoms:
                proven_here = False
                break
            model = lb.learn(atoms)
            sub = re.sub(r"\bresult\b", f"({res})", atom)
            try:
                from .ir import lower_condition
                es = lower_condition(sub)
            except Exception:
                proven_here = False
                break
            if not lb.entails(model, es):
                proven_here = False
                break
        if saw_path and proven_here:
            return True, fname
    return False, None


# publish / import

def publish_invariant(registry_path, package, name, invariant_atoms, witness,
                      key, price=1.0) -> dict:
    """List `invariant_atoms` for `package` on the market -- only after
    proving each atom against the package's CURRENT files (listing rule
    above). Writes a versioned, HMAC-signed, hash-chained entry into the
    "market" section of the registry file (registry.load_registry /
    save_registry stay compatible -- the section is just another key).

    `witness`: an arbitrary proof witness string (e.g. the source the
    atoms were proven against); only its sha256 is stored. `price`: the
    publisher's asking price, recorded as-is (see quote() for the honest pricing heuristic)."""

    lb = LinearBackend()
    pkg_name, files = _package_files(registry_path, package)
    atoms = [str(a) for a in (invariant_atoms or [])]
    if not atoms:
        raise InvMarketError(
            f"invmarket: refusing to publish an empty invariant for "
            f"{pkg_name!r}/{name!r} -- a market entry must prove something")
    for atom in atoms:
        try:
            _normalize_atom_text(atom)
        except LinearError as e:
            raise InvMarketError(
                f"invmarket: invariant atom {atom!r} is outside the linear "
                f"fragment ({e}); an unprovable invariant is never listed")
        provable, fname = _atom_provable(files, atom, lb)
        if not provable:
            raise InvMarketError(
                f"invmarket: invariant {atom!r} is NOT provable for "
                f"package {pkg_name!r}'s current files (no file has every "
                f"path entailing it) -- refusing to list an unproven "
                f"invariant as if it were proven")
    # stored atoms are the normalized solver form: raw text like
    # 'result >= n' is opaque to parse_atom and could never entail
    # anything at discharge time.
    stored_atoms = [_normalize_atom_text(a) for a in atoms]
    registry = load_registry(registry_path)
    section = registry.setdefault(MARKET_SECTION, {"entries": []})
    entries = section.setdefault("entries", [])
    prev = entries[-1] if entries else None
    version = 1 + max((e["version"] for e in entries
                       if e.get("package") == pkg_name
                       and e.get("name") == name), default=0)
    witness_sha = hashlib.sha256(str(witness).encode()).hexdigest()
    body = {"package": pkg_name, "name": name, "atoms": stored_atoms,
            "witness_sha": witness_sha, "price": float(price),
            "version": version,
            "prev": (hashlib.sha256(canonical_json(prev).encode()).hexdigest()
                     if prev is not None else None)}
    entry = {**body, "signature": hmac_sign(body, key)}
    entries.append(entry)
    save_registry(registry_path, registry)
    return {"status": "published", "package": pkg_name, "name": name,
            "version": version, "atoms": stored_atoms,
            "entry_sha256": hashlib.sha256(
                canonical_json(entry).encode()).hexdigest()}


def import_invariants(registry_path, package=None, key=None) -> list:
    """Verify every entry's signature and hash chain, then return the
    entries (optionally filtered by package). A tampered, unsigned, or
    chain-breaking entry is a loud InvMarketError naming the package and
    entry -- never silently dropped: trading on a tampered book is worse
    than refusing to trade.

    `key=None` falls back to the module demo key (loudly documented);
    pass the real key in any serious use."""
    key = key or DEFAULT_KEY
    registry = load_registry(registry_path)
    section = registry.get(MARKET_SECTION) or {}
    entries = section.get("entries", []) or []
    verified, prev = [], None
    for i, entry in enumerate(entries):
        pkg, nm = entry.get("package"), entry.get("name")
        label = f"{pkg!r}/{nm!r} (book index {i})"
        if not isinstance(entry, dict) or "signature" not in entry:
            raise InvMarketError(
                f"invmarket: market entry {label} is unsigned -- refusing "
                f"to trade on an unauthenticated book")
        body = {k: v for k, v in entry.items() if k != "signature"}
        if not hmac_verify(body, key, entry.get("signature")):
            raise InvMarketError(
                f"invmarket: market entry {label} failed its signature "
                f"check -- tampered or wrong key; refusing to trade on a "
                f"tampered book")
        if prev is None:
            if entry.get("prev") is not None:
                raise InvMarketError(
                    f"invmarket: first market entry {label} carries a "
                    f"'prev' pointer -- the book is not anchored at genesis")
        else:
            expected = hashlib.sha256(
                canonical_json(prev).encode()).hexdigest()
            if entry.get("prev") != expected:
                raise InvMarketError(
                    f"invmarket: market entry {label} breaks the hash "
                    f"chain (prev mismatch) -- the book was rewritten; "
                    f"refusing to trade on it")
        prev = entry
        if package is None or pkg == package:
            verified.append(entry)
    return verified

def discharge(obligations, market, lb=None) -> dict:
    """Try to discharge each obligation atom from market-proven invariants:
    for each entry, do the entry's atoms entail the obligation? Verdicts:
      proved-by-market -- some entry's proven atoms entail it (named)
      open             -- linear, but nothing in the market entails it
      unknown          -- outside the linear fragment; the engine refuses
                         to guess, and says so."""
    lb = lb or LinearBackend()
    from .ir import lower_condition
    results = []
    for ob in obligations:
        row = {"obligation": ob, "discharged_by": None, "verdict": None}
        try:
            _normalize_atom_text(ob)
        except LinearError as e:
            row["verdict"] = "unknown"
            row["reason"] = (f"obligation {ob!r} is outside the linear "
                             f"fragment ({e}) -- the market engine refuses "
                             f"to guess at non-linear obligations")
            results.append(row)
            continue
        es = None
        try:
            es = lower_condition(ob)
        except Exception:
            pass
        for entry in market:
            market_atoms = []
            for a in entry.get("atoms", []):
                try:
                    market_atoms.append(_normalize_atom_text(a))
                except LinearError:
                    continue    # non-linear book atom can entail nothing
            model = lb.learn(market_atoms)
            if es is not None and lb.entails(model, es):
                row["discharged_by"] = entry.get("name")
                row["verdict"] = "proved-by-market"
                break
        if row["verdict"] is None:
            row["verdict"] = "open"
            row["reason"] = ("no market entry's proven atoms entail this "
                             "obligation -- it stays open")
        results.append(row)
    return {"results": results,
            "discharged": sum(1 for r in results
                              if r["verdict"] == "proved-by-market"),
            "open": sum(1 for r in results if r["verdict"] == "open"),
            "unknown": sum(1 for r in results if r["verdict"] == "unknown")}


def quote(entry) -> dict:
    """Honest toy pricing: literal count x proof size, scaled by a fixed
    constant. The basis string says IN PLAIN WORDS that this is a
    documented heuristic, not a market price."""
    atoms = [str(a) for a in entry.get("atoms", [])]
    literals = len(atoms)
    proof_size = sum(len(a) for a in atoms)
    price = round(literals * max(proof_size, 1) * 0.001, 6)
    return {"price": price,
            "basis": (f"{literals} literal(s) x proof size {proof_size} "
                      f"chars x 0.001 -- documented heuristic, not a "
                      f"market price")}


def claims() -> dict:
    """Honesty manifest (the zk.is_mock_check pattern): what the market
    does and does not stand behind."""
    return {
        "proven": [
            "entries are signature-verified (HMAC-SHA256, pegrex.attest) "
            "and hash-chained at import time",
            "every listed atom was PROVABLE against the package's files at "
            "publish time (engine entailment, every path)",
        ],
        "not_proven": [
            "the invariant still holds for the package's CURRENT source -- "
            "import is not re-proof; run discharge-time entailment against "
            "fresh contracts if freshness matters",
            "price is not financial advice -- quote() is a documented "
            "toy heuristic, not a market price",
        ],
    }
