#!/usr/bin/env python3
"""Audit the checked-in JSON Schema catalog for consistency and review status."""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = ROOT / "docs" / "SCHEMA_CATALOG_AUDIT.json"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from pegrex.schema import schema_catalog


def audit(root: Path = ROOT) -> dict:
    directory = root / "pegrex" / "jsonschemas"
    files = sorted(directory.glob("*.json"))
    errors: list[str] = []
    ids: dict[str, str] = {}
    levels: dict[str, int] = {}
    def visit(schema: object, path: str) -> None:
        if not isinstance(schema, dict):
            errors.append(f"{path}: schema node must be an object")
            return
        props = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(props, dict): errors.append(f"{path}: properties must be an object")
        if not isinstance(required, list): errors.append(f"{path}: required must be a list")
        elif isinstance(props, dict):
            for key in required:
                if key not in props: errors.append(f"{path}: required field {key!r} has no property schema")
        for key, child in (props.items() if isinstance(props, dict) else []):
            visit(child, f"{path}.properties.{key}")
        items = schema.get("items")
        if isinstance(items, dict): visit(items, f"{path}.items")
        for keyword in ("anyOf", "oneOf", "allOf"):
            children = schema.get(keyword, [])
            if isinstance(children, list):
                for index, child in enumerate(children): visit(child, f"{path}.{keyword}[{index}]")
    for file in files:
        try: schema = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{file.name}: invalid JSON ({type(exc).__name__})"); continue
        if not isinstance(schema, dict):
            errors.append(f"{file.name}: root must be object"); continue
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            errors.append(f"{file.name}: missing $id")
        elif schema_id in ids:
            errors.append(f"{file.name}: duplicate $id {schema_id} also in {ids[schema_id]}")
        else: ids[schema_id] = file.name
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            errors.append(f"{file.name}: unexpected JSON Schema dialect")
        level = schema.get("x-peg-rex-validation-level", "reviewed")
        levels[level] = levels.get(level, 0) + 1
        visit(schema, file.name)
    catalog = schema_catalog()
    missing = sorted(set(catalog) - {"pegrex." + file.stem for file in files})
    extra = sorted({"pegrex." + file.stem for file in files} - set(catalog))
    if missing: errors.append("missing catalog files: " + ", ".join(missing))
    if extra: errors.append("uncatalogued schema files: " + ", ".join(extra))
    return {"schema": "pegrex.schema-catalog-audit.v1", "files": len(files),
            "catalog_entries": len(catalog), "levels": dict(sorted(levels.items())),
            "errors": errors, "passed": not errors,
            "limitations": ["structural consistency does not prove that schemas cover every runtime branch",
                            "schemas marked inferred-top-level remain provisional until manually reviewed"]}


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true",
                        help="verify catalog structure and the committed audit snapshot")
    args = parser.parse_args(argv)
    report = audit()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.check:
        snapshot = args.output or DEFAULT_REPORT
        if not report["passed"]:
            print(rendered, end="")
            return 1
        if not snapshot.exists() or snapshot.read_text(encoding="utf-8") != rendered:
            print("schema catalog audit stale -- run: "
                  "python tools/audit_public_schemas.py --output docs/SCHEMA_CATALOG_AUDIT.json")
            return 1
        print(f"schema catalog audit is fresh ({report['catalog_entries']} entries)")
        return 0
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if report["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
