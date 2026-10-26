"""Fail-closed ephemeral PoC execution with no credentials/network by default."""
from __future__ import annotations
import hashlib,json,os,shutil,signal,subprocess,tempfile
from pathlib import Path
SCHEMA="pegrex.poc-execution.v1"

def _executables(): return shutil.which("bwrap"),shutil.which("prlimit")
def sandbox_status():
    """Implement sandbox status with the module's explicit API and failure semantics."""
    bwrap,prlimit=_executables()
    available=bool(os.name=="posix" and bwrap and prlimit)
    return {"available":available,"backend":"bubblewrap+prlimit" if available else None,
            "unknowns":[] if available else ["ephemeral isolated sandbox unavailable; PoC execution refused"]}

def _plan(argv,workspace,timeout_ms,memory_mb):
    bwrap,prlimit=_executables()
    command=[bwrap,"--unshare-all","--die-with-parent","--new-session","--clearenv",
             "--cap-drop","ALL","--tmpfs","/","--proc","/proc","--dev","/dev",
             "--tmpfs","/tmp","--tmpfs","/home","--tmpfs","/root"]
    for directory in ("/usr","/lib","/lib64","/bin","/sbin"):
        if Path(directory).exists(): command += ["--ro-bind",directory,directory]
    command += ["--bind",str(workspace),"/workspace","--chdir","/workspace",
                "--setenv","PATH","/usr/bin:/bin","--setenv","PYTHONDONTWRITEBYTECODE","1","--",
                prlimit,f"--cpu={max(1,(timeout_ms+999)//1000)}",f"--as={memory_mb*1024*1024}",
                "--fsize=8000000","--"] + list(argv)
    return command

def run_poc(argv,*,files=None,timeout_ms=5000,memory_mb=256) -> dict:
    """Run only declared files in a new bubblewrap namespace; never raw shell."""
    if isinstance(argv,str) or not argv or any(not isinstance(row,str) for row in argv):
        return {"schema":SCHEMA,"status":"unknown","executed":False,"unknowns":["PoC requires argv"]}
    status=sandbox_status()
    if not status["available"]:
        return {"schema":SCHEMA,"status":"unknown","executed":False,"unknowns":status["unknowns"],"sandbox":status}
    with tempfile.TemporaryDirectory(prefix="pegrex-poc-") as directory:
        workspace=Path(directory)/"workspace";workspace.mkdir()
        try:
            for name,content in (files or {}).items():
                path=Path(name)
                if path.is_absolute() or ".." in path.parts: raise ValueError("unsafe PoC file path")
                target=workspace/path;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(content.encode() if isinstance(content,str) else bytes(content))
            plan=_plan(argv,workspace,timeout_ms,memory_mb)
            output=Path(directory)/"output"
            with output.open("wb") as stream:
                process=subprocess.Popen(plan,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,
                                         env={},start_new_session=True)
                try: process.wait(timeout=timeout_ms/1000)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL);process.wait()
                    return {"schema":SCHEMA,"status":"unknown","executed":True,"confirmed":False,
                            "unknowns":["PoC timeout"],"sandbox":{"ephemeral":True,"isolated":True,"no_credentials":True,"no_network":True}}
            evidence=output.read_bytes()[:8000].decode(errors="replace")
            if process.returncode and evidence.lstrip().startswith(("bwrap:", "prlimit:")):
                return {"schema":SCHEMA,"status":"unknown","executed":False,"confirmed":False,
                        "evidence":evidence,"unknowns":["isolated sandbox setup failed; PoC payload was not executed"],
                        "sandbox":{"backend":"bubblewrap+prlimit","setup_failed":True}}
        except (OSError,ValueError) as error:
            return {"schema":SCHEMA,"status":"unknown","executed":False,"unknowns":[str(error)]}
    return {"schema":SCHEMA,"status":"reproduced" if process.returncode==0 else "not-reproduced",
            "executed":True,"confirmed":process.returncode==0,"returncode":process.returncode,
            "evidence":evidence,"unknowns":[],
            "sandbox":{"backend":"bubblewrap+prlimit","ephemeral":True,"isolated":True,
                       "no_credentials":True,"no_network":True,"argv_only":True}}
