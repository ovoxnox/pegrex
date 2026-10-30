"""Workspace path confinement and bounded provenance helpers."""
from pathlib import Path
import hashlib
from .limits import MAX_ARTIFACT_BYTES
_NAMES={"path","root","before_path","after_path","before_root","after_root","previous_root","lockfile","spec_path","source_path","ir_path","staging","candidate_root"}
def resolve_workspace_path(workspace,value):
    if not isinstance(value,str) or not value or len(value)>4096: raise ValueError("path argument must be a non-empty bounded string")
    path=Path(value); path=path if path.is_absolute() else workspace/path; lexical=Path(path.absolute())
    try: relative=lexical.relative_to(workspace)
    except ValueError as exc: raise ValueError("path escapes tool workspace") from exc
    current=workspace
    for part in relative.parts:
        current=current/part
        if current.is_symlink(): raise ValueError("symlink paths are not accepted by the Tools API")
    resolved=lexical.resolve(strict=False)
    try: resolved.relative_to(workspace)
    except ValueError as exc: raise ValueError("path escapes tool workspace") from exc
    return str(resolved)
def confine_paths(spec,arguments,workspace):
    result=dict(arguments)
    for name in spec.path_arguments:
        if name not in result: continue
        value=result[name]
        if isinstance(value,str): result[name]=resolve_workspace_path(workspace,value)
        elif isinstance(value,list) and all(isinstance(x,str) for x in value): result[name]=[resolve_workspace_path(workspace,x) for x in value]
        elif isinstance(value,dict) and all(isinstance(x,str) for x in value.values()): result[name]={k:resolve_workspace_path(workspace,x) for k,x in value.items()}
        else: raise ValueError(f"path argument {name!r} has an unsupported shape")
    return result
def identity(path):
    candidate=Path(path); row={"path":str(candidate),"kind":"directory" if candidate.is_dir() else "file"}
    if candidate.is_file():
        size=candidate.stat().st_size
        if size>MAX_ARTIFACT_BYTES: row.update(kind="oversized",bytes=size,error="artifact-size-limit-exceeded"); return row
        digest=hashlib.sha256()
        with candidate.open("rb") as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b""): digest.update(chunk)
        row.update(sha256=digest.hexdigest(),bytes=size)
    elif not candidate.exists(): row.update(kind="missing",error="path does not exist")
    return row
def provenance(arguments,workspace):
    paths=[]
    for name,value in sorted(arguments.items()):
        values=[]
        if isinstance(value,str) and name in _NAMES: values=[value]
        elif name in {"subjects","subject_paths"} and isinstance(value,list): values=value
        elif name in {"materials","material_paths"} and isinstance(value,dict): values=list(value.values())
        paths.extend(identity(x) for x in values if isinstance(x,str))
    return {"workspace":str(workspace),"paths":paths}
