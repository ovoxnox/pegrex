"""
graph - unified taint/facts/twin graph

One node/edge model over the three previously-siloed graphs: taint flows
(edges: tainted-data), datalog facts (edges: calls/assigns), and the twin
(edges: reaches/owns). A query answers from one traversal: "which endpoints
can write to the users table without auth?" = backward reachability to
endpoint nodes, filtered by absence of an auth edge on the path. Paths
without auth are findings; absence of the table is unknown -- never a
clean bill by silence."""

from __future__ import annotations


def build_graph(taint_edges=(), fact_edges=(), twin_edges=(),
                owners=None):
    nodes, edges = set(), []
    for kind, src, dst in list(taint_edges) + list(fact_edges) + list(twin_edges):
        nodes |= {src, dst}
        edges.append({"kind": kind, "src": src, "dst": dst})
    for n, o in (owners or {}).items():
        nodes.add(n)
    return {"nodes": sorted(nodes), "edges": edges,
            "owners": owners or {}}


def query_writers(graph, table, require_auth=True):
    """Functions that can reach `table`, split by presence of an auth edge
    on some path. require_auth=True -> unauth paths are findings."""
    # writers = FUNCTION nodes: sources of calls/reaches edges into the
    # table. Taint data-flow edges provide context, not writers.
    writers = sorted({e["src"] for e in graph["edges"]
                      if e["dst"] == table and e["kind"] in ("calls", "reaches")})
    if not writers:
        return {"verdict": "unknown",
                "reason": f"no edges to {table!r} in this graph"}
    findings = []
    authorized = []
    for w in writers:
        authed = any(e["kind"] == "auth" and e["src"] == w
                     for e in graph["edges"])
        (authorized if authed else findings).append(w)
    return {"verdict": "ok", "table": table,
            "unauthorized_writers": findings,
            "authorized_writers": authorized}
