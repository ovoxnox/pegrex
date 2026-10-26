"""
gatepipe — anti-hallucination compiler as a service 

║  Received code is parsed and converted to path contracts by the pegrex  
║  engine -- that is the entire analysis. A refusal carries a             
║  next_turn_prompt that embeds the COUNTEREXAMPLE INPUT VALUES and the   
║  FAILING CONTRACT as an explicit correction instruction for the         
║  generating LLM ("Your previous code violated ... at input ...").       
║  The HTTP service binds LOOPBACK INTERFACES ONLY: binding 0.0.0.0 is a  
║  loud GatePipeError (the analyzer must never be exposed to a network)."""

from __future__ import annotations

import http.server
import json
import pathlib
import shutil
import sys
import tempfile
import threading

from .attest import hmac_sign
from .tv import PROVED

LOCALHOST_OK = {"127.0.0.1", "localhost", "::1"}
HEALTH = {"ok": True, "engine": "pegrex",
          "posture": "analysis-only; no code execution"}


class GatePipeError(ValueError):
    """Loud refusal from the gate -- never a silent 500."""


def _stage(code: str, lang: str):
    """Write `code` to a private temp file and extract path contracts.
    The code is never executed -- it is only READ by the parser."""
    tmp = tempfile.mkdtemp(prefix="gatepipe-")
    from .languages import get_language
    spec = get_language(lang)
    suffix = spec.extensions[0] if spec.extensions else ".txt"
    path = pathlib.Path(tmp) / ("snippet" + suffix)
    path.write_text(code, encoding="utf-8")
    from . import api
    contracts = api.contracts(str(path), lang)
    return tmp, path, contracts


def _linear_value(expr: str, values: dict):
    """Evaluate a LINEAR result expression over concrete model values --
    pure integer arithmetic done by the engine's own IR, never by running
    the received code. None when the expression is outside the fragment."""
    try:
        from .ir import linearize, parse_expr, to_sym
        lin = linearize(to_sym(parse_expr(str(expr))))
        if lin is None:
            return None
        coeffs, const = lin
        return int(sum(c * values.get(v, 0) for v, c in coeffs.items())
                   + const)
    except Exception:
        return None


def _counterexample(contracts, claim):
    """For a REFUTED claim: find the candidate that is VIOLATED on some
    path and produce a concrete counterexample from that path's linear
    constraints (engine model -- analysis, not execution)."""
    from .ir import lower_condition
    from .linsolve import LinearBackend
    from .nlspec import propose
    from .refine import _neg, _norm_constraint
    from .linsolve import parse_atom
    lb = LinearBackend()
    for cand in propose(claim):
        for cs, res in contracts:
            atoms = []
            for c in cs:
                n = _norm_constraint(str(c))
                try:
                    parse_atom(n)
                    atoms.append(n)
                except Exception:
                    pass
            model = lb.learn(atoms)
            try:
                sub = __import__("re").sub(r"\bresult\b", f"({res})", cand)
                es = lower_condition(sub)
                neg_es = _neg(es)
            except Exception:
                continue
            if lb.entails(model, neg_es):       # path |= ~contract: violated
                values = model.model() or {}
                rexpr = str(res).strip()
                return {"contract": cand,
                        "inputs": {k: int(v) for k, v in values.items()},
                        "path": sorted(map(str, cs)),
                        "result_expr": rexpr,
                        "result_value": _linear_value(rexpr, values)}, cand
    return None, None


def _next_turn_prompt(claim, failing, cx):
    """The explicit correction instruction handed back to the generating
    LLM: names the failing contract, the counterexample INPUT VALUES, and
    what the code actually returns on that path."""
    if cx:
        inputs = json.dumps(cx["inputs"], sort_keys=True)
        if cx["result_value"] is not None:
            ret = f"{cx['result_expr']} = {cx['result_value']}"
        else:
            ret = cx["result_expr"]
        return (f"Your previous code violated contract {failing!r} at input "
                f"{inputs}: on path {cx['path']} it returns {ret}, which "
                f"contradicts {failing!r}. Correct the code so that "
                f"{failing!r} holds on every path, then resubmit.")
    return (f"Your previous claim {claim!r} could not be proven against "
            f"the submitted code. Reformulate the claim or fix the code so "
            f"the engine can discharge it, then resubmit.")


def gate(code: str, lang="python", claim=None, fn_name=None) -> dict:
    """The pure gate: parse + contracts (+ NL-claim discharge when a claim
    is given, reusing antihalluc.compile_nl, which already refuses loudly).

    verdict "verified" -> {"contracts", "paths", ...}
    verdict "refused"  -> {"refusal", "counterexample"?, "failing_contract"?,
                           "next_turn_prompt", ...}"""
    if not isinstance(code, str) or not code.strip():
        return {"verdict": "refused",
                "refusal": "gatepipe: empty code -- nothing to analyze",
                "next_turn_prompt": "Submit non-empty source code."}
    tmp = None
    try:
        try:
            tmp, path, contracts = _stage(code, lang)
        except Exception as e:
            return {"verdict": "refused",
                    "refusal": f"gatepipe: analysis refused: "
                               f"{type(e).__name__}: {str(e)[:200]}",
                    "next_turn_prompt": "Submit syntactically valid code "
                                        f"for language {lang!r}; the parser "
                                        "could not read it."}
        payload = {
            "contracts": [[sorted(map(str, cs)), str(res)]
                          for cs, res in contracts],
            "paths": [sorted(map(str, cs)) for cs, _ in contracts],
        }
        if claim is None:
            return {"verdict": "verified", "claim": None, **payload}
        from .antihalluc import compile_nl
        res = compile_nl(claim, str(path), fn_name)
        if res["verdict"] == PROVED:
            return {"verdict": "verified", "claim": claim,
                    "proven_candidates": list(dict.fromkeys(
                        res.get("proven_candidates", []))),
                    **payload}
        if res["verdict"] == "refuted":
            cx, failing = _counterexample(contracts, claim)
            reason = res.get("reason", "no candidate discharged on any path")
            return {"verdict": "refused",
                    "refusal": f"gatepipe: claim refused: {reason}",
                    "counterexample": cx,
                    "failing_contract": failing,
                    "next_turn_prompt": _next_turn_prompt(claim, failing, cx),
                    **payload}
        return {"verdict": "refused",
                "refusal": f"gatepipe: claim undecidable on the analyzed "
                           f"fragment: {res.get('reason')}",
                "next_turn_prompt": _next_turn_prompt(claim, None, None),
                **payload}
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def serve(host="127.0.0.1", port=0, key=None) -> dict:
    """Loopback-only analysis service (stdlib ThreadingHTTPServer).

    # LOCALHOST-ONLY POSTURE: binding anything but a loopback interface
    is a loud GatePipeError. The analyzer receives arbitrary code from
    generating agents; exposing it to a network would expose the host.

    POST /gate   {code, lang?, claim?, fn_name?} -> 200 {"status":
                 "verified", ...} | 422 {"status": "refused", ...}
    GET  /health -> {"ok": true, "engine": "pegrex",
                 "posture": "analysis-only; no code execution"}
    anything else -> 404 JSON. Malformed JSON -> 400 JSON, connection kept
    alive (HTTP/1.1 + Content-Length).

    With `key` set, every response carries an HMAC-SHA256 signature over
    its JSON body (pegrex.attest) so agents can authenticate the verdict."""
    if host not in LOCALHOST_OK:
        raise GatePipeError(
            f"gatepipe: localhost-only posture -- refusing to bind "
            f"{host!r}. Received code is analyzed, never executed, and the "
            f"analyzer must not be reachable from a network; use "
            f"127.0.0.1 (or localhost / ::1).")

    class Handler(http.server.BaseHTTPRequestHandler):
        """Handler - see module docstring."""
        protocol_version = "HTTP/1.1"     # keep-alive, always with length

        def log_message(self, *args):
            """log message(): see module docstring."""
            pass

        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True

        def do_GET(self):
            """do GET(): see module docstring."""
            if self.path == "/health":
                self._send(200, dict(HEALTH))
            else:
                self._send(404, {"status": "not found", "path": self.path})

        def do_POST(self):
            # Drain the request body first: responding on a kept-alive
            # connection without reading the body would leave it in the
            # buffer, and the next request line on this connection would
            # read that garbage.
            """do POST(): see module docstring."""
            try:
                length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                length = 0
            raw = self.rfile.read(length)
            if self.path != "/gate":
                self._send(404, {"status": "not found", "path": self.path})
                return
            try:
                req = json.loads(raw.decode() if isinstance(raw, bytes)
                                 else (raw or ""))
                if not isinstance(req, dict):
                    raise ValueError("request body must be a JSON object")
            except (ValueError, TypeError) as e:
                self._send(400, {"status": "error",
                                 "reason": f"malformed JSON body: {e}"})
                return
            out = gate(req.get("code", ""),
                       lang=req.get("lang", "python"),
                       claim=req.get("claim"),
                       fn_name=req.get("fn_name"))
            payload = {"status": out["verdict"], **out}
            if key is not None:
                payload["signature"] = hmac_sign(
                    {k: v for k, v in payload.items()}, key)
            self._send(200 if out["verdict"] == "verified" else 422,
                       payload)

    httpd = http.server.ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    def shutdown():
        """shutdown(): see module docstring."""
        httpd.shutdown()
        httpd.server_close()

    return {"url": f"http://{host}:{httpd.server_address[1]}",
            "thread": thread, "shutdown": shutdown, "server": httpd}


def stop(server_dict) -> None:
    """Shut a serve() dict down and join its thread."""
    server_dict["shutdown"]()
    server_dict["thread"].join(timeout=5)


def filter_stdio() -> None:
    """Pipe mode: read JSON lines {code, lang?, claim?, fn_name?} from
    stdin, write verdict JSON lines to stdout -- for editor/agent pipes.
    Malformed lines produce an error verdict line, never a crash."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            if not isinstance(req, dict):
                raise ValueError("line must be a JSON object")
        except (ValueError, TypeError) as e:
            print(json.dumps({"status": "error",
                              "reason": f"malformed JSON line: {e}"}),
                  flush=True)
            continue
        out = gate(req.get("code", ""),
                   lang=req.get("lang", "python"),
                   claim=req.get("claim"),
                   fn_name=req.get("fn_name"))
        print(json.dumps(out), flush=True)
