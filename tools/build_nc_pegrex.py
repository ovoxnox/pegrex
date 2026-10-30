#!/usr/bin/env python3
"""Build the offline neural-codegen adapter against a pinned upstream checkout."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()
    upstream = Path(args.upstream).resolve()
    for crate in ("nc-parser", "nc-ir", "nc-codegen"):
        if not (upstream / "crates" / crate / "Cargo.toml").is_file():
            raise ValueError(f"upstream lacks crates/{crate}/Cargo.toml")
    work = Path(args.work_dir).resolve()
    if work.is_symlink():
        raise ValueError("work directory must not be a symlink")
    (work / "src").mkdir(parents=True, exist_ok=True)
    template = (ROOT / "nc_pegrex" / "Cargo.toml.template").read_text(encoding="utf-8")
    (work / "Cargo.toml").write_text(
        template.replace("__NEURAL_CODEGEN_ROOT__", upstream.as_posix()), encoding="utf-8")
    shutil.copyfile(ROOT / "nc_pegrex" / "src" / "main.rs", work / "src" / "main.rs")
    subprocess.run(["cargo", "build", "--release", "--offline", "--manifest-path",
                    str(work / "Cargo.toml"), "--target-dir", str(work / "target")],
                   cwd=work, check=True, timeout=300)
    binary = work / "target" / "release" / ("nc-pegrex.exe" if os.name == "nt" else "nc-pegrex")
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(binary, output)
    provenance = {"schema": "pegrex.neural-codegen-adapter-build.v1",
                  "upstream": str(upstream), "binary": str(output),
                  "binary_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                  "offline": True}
    output.with_name(output.name + ".provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(provenance, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
