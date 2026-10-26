"vapi - time-bounded verify-or-refuse API."

import threading
import time

from .tv import UNKNOWN, wrap


class LatencyTracker:
    def __init__(self):
        self.calls = 0
        self.sum_ms = 0.0
        self.deadline_misses = 0

    def record(self, ms, met_deadline):
        """Implement record with the module's explicit API and failure semantics."""
        self.calls += 1
        self.sum_ms += ms
        if not met_deadline:
            self.deadline_misses += 1

    @property
    def avg_ms(self):
        """Implement avg ms with the module's explicit API and failure semantics."""
        return round(self.sum_ms / self.calls, 2) if self.calls else 0.0


def verify_or_refuse(before_path, after_path, deadline_ms, verifier=None,
                     tracker=None):
    """Deadline-bounded verification. Returns tri-valued result."""
    from .semantics import verify_patch
    check = verifier or verify_patch
    box = {}

    def target():
        """Implement target with the module's explicit API and failure semantics."""
        try:
            box["result"] = check(before_path, after_path)
        except Exception as e:
            box["error"] = f"{type(e).__name__}: {str(e)[:140]}"

    t0 = time.perf_counter()
    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(deadline_ms / 1000.0)
    ms = (time.perf_counter() - t0) * 1000.0
    met = not th.is_alive()
    if tracker is not None:
        tracker.record(ms, met)
    if not met:
        return {"verdict": UNKNOWN,
                "reason": f"deadline {deadline_ms}ms exceeded",
                "latency_ms": round(ms, 2), "deadline_ms": deadline_ms,
                "completed": False}
    if "error" in box:
        return {"verdict": UNKNOWN, "reason": box["error"],
                "latency_ms": round(ms, 2), "deadline_ms": deadline_ms,
                "completed": False}
    out = wrap(box["result"])
    out["latency_ms"] = round(ms, 2)
    out["deadline_ms"] = deadline_ms
    out["completed"] = True
    return out
