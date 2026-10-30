"""Shared low-disclosure error policy for service-facing boundaries."""
_SAFE=("unknown tool","unknown core operation","tool arguments","unknown tool argument","missing required tool argument","argument ","path escapes tool workspace","path argument ","symlink paths","request ","source input exceeds","unsupported request","invalid source","timeout_ms must","memory_mb must","max_elements exceeds","max_results exceeds","argv exceeds","active task limit exceeded","state ")
def safe_error_message(error):
    message=str(error)
    if isinstance(error,(ValueError,TypeError)) and message.startswith(_SAFE):
        if message.startswith("path escapes tool workspace"): return "path escapes tool workspace"
        if message.startswith("symlink paths"): return "symlink paths are not accepted by the Tools API"
        if message.startswith("unknown tool"): return "unknown tool"
        if message.startswith("missing required tool argument"): return "missing required tool argument"
        if message.startswith("unknown tool argument"): return "unknown tool argument"
        if message.startswith("argument "): return "invalid tool argument"
        if message.startswith("state "): return message[:160]
        return message.split(":",1)[0][:120]
    return "internal operation failure"
def disclosed_error_message(error,*,disclose): return str(error) if disclose else safe_error_message(error)
