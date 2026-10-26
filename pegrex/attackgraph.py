"""Bounded attack-path graphs joining exposure, code, and dependencies."""
from __future__ import annotations
from collections import deque
import hashlib, json
SCHEMA = "pegrex.attack-path-graph.v1"

class AttackPathGraph:
    def __init__(self): self.nodes, self.edges, self.unknowns = {}, [], []
    def node(self, identity, kind, **evidence):
        """Implement node with the module's explicit API and failure semantics."""
        self.nodes[identity] = {"id": identity, "kind": kind, "evidence": evidence}
        return identity
    def edge(self, source, target, kind, **evidence):
        """Implement edge with the module's explicit API and failure semantics."""
        if source not in self.nodes or target not in self.nodes:
            self.unknowns.append(f"edge endpoint missing: {source} -> {target}"); return
        self.edges.append({"source": source, "target": target, "kind": kind, "evidence": evidence})
    def paths(self, *, max_paths=100, max_depth=20):
        """Implement paths with the module's explicit API and failure semantics."""
        adjacency = {}
        for edge in self.edges: adjacency.setdefault(edge["source"], []).append(edge)
        starts = sorted(key for key,row in self.nodes.items() if row["kind"] in {"exposure", "source", "identity"})
        results, capped = [], False
        for start in starts:
            queue=deque([(start,[start],[])])
            while queue:
                node,nodes,edges=queue.popleft()
                if self.nodes[node]["kind"] in {"sink", "reachable-vulnerability"} and len(nodes)>1:
                    if len(results)>=max_paths:
                        capped=True; break
                    results.append({"nodes":nodes,"edges":edges,"evidence_strength":"static-graph-path"}); continue
                if len(edges)>=max_depth: capped=True; continue
                for edge in sorted(adjacency.get(node,[]),key=lambda row:(row["target"],row["kind"])):
                    if edge["target"] in nodes: continue
                    queue.append((edge["target"],nodes+[edge["target"]],edges+[edge]))
                    if len(results)>=max_paths: capped=True; break
                if capped: break
            if capped: break
        unknowns=list(self.unknowns)
        if capped: unknowns.append("attack-path bound reached; path set incomplete"); results=[]
        return {"schema":SCHEMA,"schema_version":1,"complete":not capped,
                "verdict":"unknown" if unknowns else "ok","paths":results,"unknowns":sorted(set(unknowns))}
    def payload(self):
        """Implement payload with the module's explicit API and failure semantics."""
        return {"schema":SCHEMA,"schema_version":1,"nodes":[self.nodes[k] for k in sorted(self.nodes)],
                "edges":sorted(self.edges,key=lambda row:(row["source"],row["target"],row["kind"])),
                "unknowns":sorted(set(self.unknowns))}


def build_attack_graph(*, assets=(), identities=(), exposures=(), dependencies=(), flow_reports=()) -> AttackPathGraph:
    """Implement build attack graph with the module's explicit API and failure semantics."""
    graph=AttackPathGraph()
    for row in assets: graph.node(row["id"], "asset", **{k:v for k,v in row.items() if k!="id"})
    for row in identities:
        graph.node(row["id"],"identity",**{k:v for k,v in row.items() if k!="id"})
        for asset in row.get("can_access",[]):
            if asset not in graph.nodes: graph.node(asset,"asset",inferred=True)
            graph.edge(row["id"],asset,"can-access")
    for row in exposures:
        service=row["service"]; asset=row["asset"]
        if asset not in graph.nodes: graph.node(asset,"asset",inferred=True)
        graph.node(service,"exposed-service",**row); graph.node(row.get("from","internet"),"exposure")
        graph.edge(row.get("from","internet"),service,"exposes"); graph.edge(service,asset,"reachable-service")
    for row in dependencies:
        name="dependency:"+row["name"]
        graph.node(name,"dependency",**row)
        if row.get("reachability")=="reachable":
            sink="vulnerability:"+row.get("id",row["name"]);graph.node(sink,"reachable-vulnerability",**row);graph.edge(name,sink,"reachable-vulnerable-call")
        for asset in row.get("assets",[]):
            if asset not in graph.nodes: graph.node(asset,"asset",inferred=True)
            graph.edge(asset,name,"depends-on")
    for report in flow_reports:
        for finding in report.get("findings",[]):
            file=finding.get("file","<unknown>");asset="file:"+file
            graph.node(asset,"asset",path=file)
            sink=f"sink:{finding['id']}:{file}:{finding.get('line',1)}"
            graph.node(sink,"sink",rule=finding["id"],matched_ast=finding.get("matched_ast"),strength=finding.get("evidence_strength"))
            sources=finding.get("sources") or []
            if not sources:
                graph.edge(asset,sink,"contains-sink",rule=finding["id"])
            for index,source in enumerate(sources):
                origin=f"source:{hashlib.sha256(json.dumps(source,sort_keys=True).encode()).hexdigest()[:16]}"
                graph.node(origin,"source",**source);graph.edge(origin,asset,"flows-through")
                graph.edge(asset,sink,"reaches-sink",rule=finding["id"],flow_path=finding.get("flow_path"))
    return graph
