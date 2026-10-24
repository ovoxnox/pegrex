"""
cfg

Control-flow graphs from any AST: tag names OR callables, transparent
wrappers, Rust tail-expressions as implicit returns."""

from __future__ import annotations

from dataclasses import dataclass, field

from .peg import Node

nl = chr(10)

@dataclass
class Block:
    id: int
    stmts: list = field(default_factory=list)
    term: str = "fall" # fall | branch | loopcond | ret


@dataclass
class Edge:
    src: int
    dst: int
    cond: object = None
    kind: str = "flow" # flow | then | else | body | exit | back


@dataclass
class TagSpec:
    """Dispatch table. Fields accept a tag name (str) or a callable over the
    Node-children list.  `block`/`if_`/`while_` may be callables carrying a
    `_tag` attribute (see tree_sitter_bridge._mk)."""
    block: object = "Block"
    if_: object = "If"
    while_: object = "While"
    for_: object = "For"
    try_: object = "Try"
    match_: object = "Match"
    with_: object = "With"
    return_: str = "Return"
    break_: str = "Break"
    continue_: str = "Continue"
    tail_return: tuple = ()

    _nodes = staticmethod(lambda n: [c for c in n.children
                                     if isinstance(c, Node)])

    def if_parts(self, node):
        ch = self._nodes(node)
        return (self.if_(ch) if callable(self.if_)
                else (ch[0], ch[1], ch[2] if len(ch) > 2 else None))

    def while_parts(self, node):
        ch = self._nodes(node)
        return (self.while_(ch) if callable(self.while_)
                else (ch[0], ch[1]))

    def for_parts(self, node):
        ch = self._nodes(node)
        return (self.for_(ch) if callable(self.for_)
                else (ch[0], ch[1]))


class CFG:
    """CFG - see module docstring."""
    def __init__(self) -> None:
        self.blocks: list[Block] = []
        self.edges: list[Edge] = []
        self._adj: dict = {}

    def add_block(self, stmts=(), term: str = "fall") -> int:
        self.blocks.append(Block(len(self.blocks), list(stmts), term))
        self._adj[self.blocks[-1].id] = []
        return self.blocks[-1].id

    def add_edge(self, src: int, dst: int, cond=None, kind: str = "flow") -> None:"
        e = Edge(src, dst, cond, kind)
        self.edges.append(e)
        self._adj.setdefault(src, []).append(e)

    def successors(self, b: int):
        """O(out-degree) via adjacency index (was O(E) scan)."""
        return [(e.dst, e) for e in self._adj.get(b, ())]

    def to_dot(self) -> str:
        head = "digraph cfg {"
        nodes = []
        for b in self.blocks:
            lbl = "\\l".join(getattr(x, "tag", str(x)) for x in b.stmts) or b.term
            nodes.append(f'  b{b.id} [shape=box,label="b{b.id}: {lbl}\\l"]')
        edges = [f'  b{e.src} -> b{e.dst} [label="{e.kind}"]' for e in self.edges]
        return nl.join([head, *nodes, *edges, "}"])


class CFGBuilder:"
    _TRANSPARENT = ("statement_list", "expression_statement", "statement",
                    "function_body", "statements", "infix_expression",
                    "block_expression")

    def __init__(self, spec: TagSpec | None = None) -> None:
        self.spec = spec or TagSpec()
        self.cfg = CFG()

    def build(self, node) -> CFG:
        self._stmt(node, self.cfg.add_block())
        return self.cfg

    def _dispatch(self, sp, tag):
        """(attr, callable) pairs checked in order; each returns its tag set."""
        for attr in ("if_", "while_", "for_", "try_", "match_", "with_"):
            f = getattr(sp, attr)
            if tag == f or (callable(f) and tag == getattr(f, "_tag", None)):
                return attr
        return None

    def _stmt(self, node, cur: int):
        """Returns (cur_or_None, exits). `cur` is the block normal control
        flow falls through to, or None if every path through this node
        exits early (break/continue/return) with no fallthrough. `exits`
        is a list of ("break", block) / ("continue", block) pairs pending
        propagation up to the nearest enclosing loop -- a *list*, because
        a single construct (if/match/try/with) can expose several distinct
        pending exits at once (e.g. one branch breaks, another continues)."""
        if not isinstance(node, Node):
            return cur, []
        if node.tag in self._TRANSPARENT:
            exits = []
            for ch in node.children:
                if isinstance(ch, Node):
                    cur, more = self._stmt(ch, cur)
                    exits.extend(more)
                    if cur is None:
                        return None, exits
            return cur, exits
        sp, tag = self.spec, node.tag
        if tag == "elif_clause":
            kids = [c for c in node.children if isinstance(c, Node)]
            els = kids[2] if len(kids) > 2 else None
            if els is not None and els.tag == "else_clause":
                inner = [c for c in els.children if isinstance(c, Node)]
                els = inner[-1] if inner else els
            return self._if(kids[0], kids[1], els, cur)
        if tag == sp.block:
            return self._block(node, cur)
        which = self._dispatch(sp, tag)
        if which == "if_":
            cond, then, els = sp.if_parts(node)
            return self._if(cond, then, els, cur)
        if which in ("while_", "for_"):
            cond, body = (sp.while_parts(node) if which == "while_"
                          else sp.for_parts(node))
            return self._while(cond, body, cur)
        if which == "try_":
            return self._try(node, cur)
        if which == "match_":
            return self._match(node, cur)
        if which == "with_":
            return self._with(node, cur)
        if tag == sp.return_:
            return self._terminate(cur, node)
        if tag == sp.break_:
            return None, [("break", cur)]
        if tag == sp.continue_:
            return None, [("continue", cur)]
        self.cfg.blocks[cur].stmts.append(node)
        return cur, []

    def _block(self, node, cur: int):
        kids = [c for c in node.children if isinstance(c, Node)]
        exits = []
        for i, ch in enumerate(kids):
            if cur is None:
                break # prior stmt exited unconditionally;
                      # remaining siblings are unreachable
            if i == len(kids) - 1 and self.spec.tail_return:
                inner = ch
                while inner.tag in self._TRANSPARENT and inner.children:
                    inner = inner.children[0]
                if inner.tag in self.spec.tail_return:
                    cur, more = self._terminate(cur, ch)
                    exits.extend(more)
                    return cur, exits
            cur, more = self._stmt(ch, cur)
            exits.extend(more)
        return cur, exits

    def _terminate(self, cur: int, node):
        self.cfg.blocks[cur].stmts.append(node)
        self.cfg.blocks[cur].term = "ret"
        return None, []

    def _if(self, cond, then, els, cur: int):
        self.cfg.blocks[cur].term = "branch"
        t_entry = self.cfg.add_block()
        self.cfg.add_edge(cur, t_entry, cond, "then")
        t_end, texits = self._stmt(then, t_entry)
        join_srcs = [] # (src, edge_cond, edge_kind)
        if t_end is not None:
            join_srcs.append((t_end, None, "flow"))
        eexits = []
        if els is not None:
            e_entry = self.cfg.add_block()
            self.cfg.add_edge(cur, e_entry, (cond, "else"), "else")
            e_end, eexits = self._stmt(els, e_entry)
            if e_end is not None:
                join_srcs.append((e_end, None, "flow"))
        else:
            join_srcs.append((cur, (cond, "else"), "else"))
        exits = texits + eexits
        if not join_srcs:       # every branch exits unconditionally
            return None, exits  # (break/continue/return): no join
        join = self.cfg.add_block()
        for src, c, kind in join_srcs:
            self.cfg.add_edge(src, join, c, kind)
        return join, exits

    def _while(self, cond, body, cur: int):
        self.cfg.blocks[cur].term = "loopcond"
        body_entry = self.cfg.add_block()
        self.cfg.add_edge(cur, body_entry, cond, "body")
        b_end, exits = self._stmt(body, body_entry)
        after = self.cfg.add_block()
        self.cfg.add_edge(cur, after, (cond, "exit"), "exit")
        if b_end is not None:
            self.cfg.add_edge(b_end, cur, kind="back")
        for kind, blk in exits:    # ALL pending breaks/continues --
            if kind == "continue": # not just the last one seen
                self.cfg.add_edge(blk, cur, kind="back")
            else: # "break"
                self.cfg.add_edge(blk, after)
        return after, []  # fully resolved at this loop level

    def _with(self, node, cur: int):
        kids = [c for c in node.children if isinstance(c, Node)]
        if not kids:
            return cur, []
        body = kids[1] if len(kids) > 1 else kids[0]
        enter = self.cfg.add_block()
        self.cfg.add_edge(cur, enter, kind="enter")
        b_end, exits = self._stmt(body, enter)
        after = self.cfg.add_block()
        if b_end is not None:
            self.cfg.add_edge(b_end, after, kind="exit")
        self.cfg.add_edge(enter, after, ("<exception>", "with"), "raise")
        return after, exits

    def _try(self, node, cur: int):
        kids = [c for c in node.children if isinstance(c, Node)]
        body = kids[0]
        handlers = [k for k in kids[1:]
                    if "except" in k.tag or k.tag == "block"]
        t_entry = self.cfg.add_block()
        self.cfg.add_edge(cur, t_entry, kind="try")
        t_end, exits = self._stmt(body, t_entry)
        join_srcs = []
        if t_end is not None:
            join_srcs.append((t_end, "noexcept"))
        for h in handlers:
            h_entry = self.cfg.add_block()
            self.cfg.add_edge(t_entry, h_entry, ("<exception>", h.tag), "raise")
            h_end, hexits = self._stmt(h, h_entry)
            exits.extend(hexits)
            if h_end is not None:
                join_srcs.append((h_end, "flow"))
        if not join_srcs:
            return None, exits
        join = self.cfg.add_block()
        for src, kind in join_srcs:
            self.cfg.add_edge(src, join, kind=kind)
        return join, exits

    def _match(self, node, cur: int):
        kids = [c for c in node.children if isinstance(c, Node)]
        subject = kids[0] if kids else None
        arms = []
        for k in kids[1:]:
            arms.extend(c for c in k.children
                        if isinstance(c, Node)
                        and ("case" in c.tag or c.tag == "switch_case"))
        self.cfg.blocks[cur].term = "branch"
        exits = []
        join_srcs = []
        for arm in arms:
            sub = [c for c in arm.children if isinstance(c, Node)]
            inner = sub[-1] if sub else arm
            entry = self.cfg.add_block()
            self.cfg.add_edge(cur, entry, (subject, arm), "arm")
            end, aexits = self._stmt(inner, entry)
            exits.extend(aexits)
            if end is not None:
                join_srcs.append(end)
        if not join_srcs:
            return None, exits
        join = self.cfg.add_block()
        for src in join_srcs:
            self.cfg.add_edge(src, join)
        return join, exits


def enumerate_paths_lazy(node, tagspec=None, unroll: int = 1):
    """Lazy path enumeration: O(path-length) state, no edge objects."""
    spec = tagspec or TagSpec()
    counter = [0]

    def block():
        counter[0] += 1
        return counter[0]

    def rec(n, path, visits):
        if not isinstance(n, Node):
            return
        if n.tag in CFGBuilder._TRANSPARENT:
            acc = [block()]
            for ch in n.children:
                if isinstance(ch, Node):
                    yield from rec(ch, path + acc, visits)
            return
        tag = n.tag
        kids = [x for x in n.children if isinstance(x, Node)]
        if tag == spec.return_:
            yield path + [block()]
            return
        if tag == spec.break_:
            yield path + [("break",)]
            return
        if tag == spec.block:
            acc = [block()]
            for ch in kids:
                yield from rec(ch, path + acc, visits)
            return
        if tag == spec.if_ or (callable(spec.if_)
                               and tag == getattr(spec.if_, "_tag", None)):
            cond, then, els = spec.if_parts(n)
            yield from rec(then, path + [block()], visits)
            if els is not None:
                yield from rec(els, path + [block()], visits)
            else:
                yield path + [block()]
            return
        if tag == spec.while_ or (callable(spec.while_)
                                  and tag == getattr(spec.while_, "_tag", None)):
            cond, body = spec.while_parts(n)
            head = block()
            yield path + [head]
            key = id(n)
            if visits.get(key, 0) < unroll:
                yield from rec(body, path + [head, block()],
                               {**visits, key: visits.get(key, 0) + 1})
            return
        if tag == spec.for_ or (callable(spec.for_)
                                and tag == getattr(spec.for_, "_tag", None)):
            cond, body = spec.for_parts(n)
            head = block()
            yield path + [head] # zero-iteration path
            key = id(n)
            if visits.get(key, 0) < unroll:
                yield from rec(body, path + [head, block()],
                               {**visits, key: visits.get(key, 0) + 1})
            return
        yield path + [block()]

    yield from rec(node, [], {})
