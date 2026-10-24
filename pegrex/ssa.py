"Single Static Assignment: mutable flows -> versioned immutable state."

from __future__ import annotations

from typing import Callable

from .sym import Sym


def to_ssa(cfg, assign_info: Callable) -> tuple[dict[int, dict[str, Sym]], list]:
    """assign_info(stmt) -> (var, repr) | None.  Returns (env per block, phis)."""
    versions: dict[str, int] = {}
    block_env: dict[int, dict[str, Sym]] = {}
    phis: list[tuple[int, str, list[str]]] = []

    def bump(var: str) -> Sym:
        """bump(var): see module docstring."""
        versions[var] = versions.get(var, 0) + 1
        return Sym(f"{var}@{versions[var]}")

    for blk in cfg.blocks:   # blocks are already in order
        env = dict(block_env.get(blk.id, {}))
        for st in blk.stmts:
            if (info := assign_info(st)):
                env[info[0]] = bump(info[0])
        block_env[blk.id] = env
        for dst, _e in cfg.successors(blk.id):  # propagate; record phi conflicts
            if dst not in block_env:
                block_env[dst] = dict(env)
                continue
            cur = block_env[dst]
            for var, sym in env.items():
                if var in cur and str(cur[var]) != str(sym):
                    incoming = sorted({str(cur[var]), str(sym)})
                    if (dst, var, incoming) not in phis:
                        phis.append((dst, var, incoming))
                else:
                    cur.setdefault(var, sym)
    return block_env, phis
