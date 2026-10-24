"""
sqlrel — SQL <-> ORM equivalence 

║  A small SQL SELECT subset parsed to a relational record {table, 
║  projection, where-atoms}; a Django-style builder lowers to the same    
║  record. Equivalence: same table, same projection (order-insensitive),  
║  and where-conditions mutually entailing (engine, both directions). 
║  One-direction implication is not equivalence -- refused. Invalid SQL   
║  refuses loudly."""

from __future__ import annotations

import re

from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of

DEFAULT_LB = LinearBackend()

_TOK = re.compile(r"\s*(SELECT|FROM|WHERE|AND|OR|,|[A-Za-z_]\w*|\d+|<=|>=|=|<|>)",
                  re.I)


def _lex(text):
    out, i = [], 0
    while i < len(text):
        m = _TOK.match(text, i)
        if not m:
            if text[i:].strip() == "":
                break
            raise ValueError(f"sqlrel: cannot tokenize at {text[i:]!r}")
        out.append(m.group(1))
        i = m.end()
    return out


class SQLParseError(ValueError):
    pass


def parse_select(text):
    """SELECT cols FROM table [WHERE cond] -> relational record."""
    toks = _lex(text)
    pos = [0]
    def peek():
        """peek(): see module docstring."""
        return toks[pos[0]].upper() if pos[0] < len(toks) else None
    def next_():
        """next (): see module docstring."""
        t = toks[pos[0]]; pos[0] += 1; return t
    def expect(w):
        """expect(w): see module docstring."""
        if peek() != w:
            raise SQLParseError(f"sqlrel: expected {w}, got {peek()}")
        next_()
    expect("SELECT")
    cols = [next_()]
    while peek() == ",":
        next_()
        cols.append(next_())
    expect("FROM")
    table = next_()
    where = []
    if peek() == "WHERE":
        next_()
        or_groups = None
        def cond():
            # OR separates groups; AND conjoins within a group. Only REAL
            # disjunctions shape the record -- a pure AND condition keeps
            # or_groups None (the m136 lesson).
            nonlocal or_groups
            groups = [cmp_()]
            saw_or = False
            while peek() in ("AND", "OR"):
                op = next_().upper()
                if op == "AND":
                    groups[-1] += cmp_()
                else:
                    saw_or = True
                    groups.append(cmp_())
            if saw_or:
                or_groups = groups
            return [a for g in groups for a in g]
        def cmp_():
            col = next_()
            if peek() not in ("=", "<", ">", "<=", ">="):
                raise SQLParseError(f"sqlrel: expected comparison, got {peek()}")
            op = next_()
            val = next_()
            if not val.isdigit():
                raise SQLParseError("sqlrel: only numeric constants in WHERE")
            return atoms_of(lower_condition(f"{col} {op} {val}"))
        where = cond()
    if pos[0] != len(toks):
        raise SQLParseError(f"sqlrel: trailing tokens {toks[pos[0]:]}")
    return {"table": table, "projection": sorted(cols), "where": where,
            "or_groups": or_groups}


class Table:
    """Django-style builder lowering to the same relational record."""

    def __init__(self, name):
        self.name = name
        self.conds = []

    def filter(self, **kw):
        for key, val in kw.items():
            col, _, op = key.partition("__")
            m = {"gt": ">", "lt": "<", "gte": ">=", "lte": "<=", "eq": "="}
            if op not in m:
                raise ValueError(f"sqlrel: unknown filter op {op!r}")
            self.conds += atoms_of(lower_condition(f"{col} {m[op]} {val}"))
        return self

    def any_of(self, *conds):
        """OR disjunction: EACH (col, op, val) triple is its own branch."""
        m = {"gt": ">", "lt": "<", "gte": ">=", "lte": "<=", "eq": "="}
        self.or_groups = getattr(self, "or_groups", None) or []
        for col, op, val in conds:
            branch = atoms_of(lower_condition(f"{col} {m[op]} {val}"))
            self.or_groups.append(branch)      # one group PER triple
            self.conds += branch
        return self

    def values(self, *cols):
        return {"table": self.name, "projection": sorted(cols),
                "where": list(self.conds),
                "or_groups": getattr(self, "or_groups", None)}


def equivalent(sql_text, orm_record, lb=None) -> dict:
    """Full equivalence verdict with reasons."""
    lb = lb or DEFAULT_LB
    try:
        sql = parse_select(sql_text)
    except SQLParseError as e:
        return {"equivalent": False, "refused": str(e)}
    if sql["table"] != orm_record["table"]:
        return {"equivalent": False,
                "reason": f"table {sql['table']} != {orm_record['table']}"}
    if sql["projection"] != orm_record["projection"]:
        return {"equivalent": False,
                "reason": f"projection {sql['projection']} != {orm_record['projection']}"}
    og_a, og_b = sql.get("or_groups"), orm_record.get("or_groups")
    if og_a or og_b:
        # disjunctions compare GROUP-WISE (conjoining the flat list would
        # fake infeasibility -- the m136 lesson)
        if not (og_a and og_b) or len(og_a) != len(og_b):
            return {"equivalent": False,
                    "reason": "disjunction shape mismatch (one side has OR groups)"}
        for ga, gb in zip(og_a, og_b):
            ma, mb = lb.learn(ga), lb.learn(gb)
            if not (ma.feasible() and mb.feasible()):
                return {"equivalent": False, "reason": "vacuous OR branch"}
            if not (_entails(lb, ma, gb) and _entails(lb, mb, ga)):
                return {"equivalent": False,
                        "reason": "OR branches not equivalent"}
        return {"equivalent": True, "or_groups": len(og_a)}
    ma = lb.learn(sql["where"])
    mb = lb.learn(orm_record["where"])
    if not (ma.feasible() and mb.feasible()):
        return {"equivalent": False, "reason": "empty result set (vacuous)"}
    a_implies_b = _entails(lb, ma, orm_record["where"])
    b_implies_a = _entails(lb, mb, sql["where"])
    if a_implies_b and b_implies_a:
        return {"equivalent": True,
                "where": sorted(map(str, sql["where"]))}
    return {"equivalent": False,
            "reason": "one-directional implication only",
            "sql_implies_orm": a_implies_b, "orm_implies_sql": b_implies_a}


def _entails(lb, model, where_atoms):
    if not where_atoms:
        return True
    from .sym import And
    conds = []
    for a in where_atoms:
        try:
            conds.append(lower_condition(a))
        except Exception:
            return False
    conj = And(*conds) if len(conds) > 1 else conds[0]
    try:
        return lb.entails(model, conj)
    except Exception:
        return False
