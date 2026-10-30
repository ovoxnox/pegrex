"""Self-contained offline CFG/path-evidence explorer.

The viewer is a convenience UI, not a proof checker. Data is serialized into a
non-executable JSON script element and all labels are assigned with textContent.
"""
from __future__ import annotations

import json
from pathlib import Path


def _safe_json(value: object) -> str:
    """Serialize JSON safe to embed in HTML without closing the script element."""
    return (json.dumps(value, ensure_ascii=False, default=str)
            .replace("&", "\\u0026").replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def render_explorer(document: dict, output: str | Path) -> Path:
    """Write an interactive, self-contained offline CFG/evidence explorer.

    Accepted optional graph keys are ``nodes`` (id, label, kind, detail) and
    ``edges`` (source, target, label). The full JSON evidence remains searchable.
    Unknown graph shapes are shown as evidence only rather than guessed.
    """
    payload = _safe_json(document)
    page = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>PegRex evidence explorer</title>
<style>
:root{color-scheme:light dark}body{font:15px system-ui;max-width:1400px;margin:1.5rem auto;padding:0 1rem;color:CanvasText;background:Canvas}
header{display:flex;gap:1rem;align-items:center;flex-wrap:wrap}input{padding:.65rem;min-width:16rem;flex:1}button{padding:.5rem .8rem;cursor:pointer}
main{display:grid;grid-template-columns:minmax(0,2fr) minmax(18rem,1fr);gap:1rem;margin-top:1rem}.panel{border:1px solid #8886;border-radius:10px;padding:.75rem;min-width:0}
#graph{width:100%;min-height:260px;max-height:70vh;overflow:auto}svg{width:100%;height:100%;min-height:260px}.node{cursor:pointer}.node rect{fill:Canvas;stroke:#7b8794;stroke-width:1.5}.node.selected rect{stroke:#d97706;stroke-width:3}.node text{fill:CanvasText;font-size:12px;pointer-events:none}.edge{stroke:#89939f;stroke-width:1.4;fill:none}.edge-label{fill:CanvasText;font-size:10px}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:65vh;overflow:auto;margin:0}.muted{opacity:.75}.pill{border:1px solid #8888;border-radius:999px;padding:.15rem .5rem;font-size:.8rem}
@media(max-width:850px){main{grid-template-columns:1fr}}
</style></head><body><header><div><h1>PegRex evidence explorer</h1><p class="muted">Interactive control-flow and evidence view. It does not verify proofs.</p></div><span class="pill" id="graph-status">Loading graph</span></header>
<label for="filter">Filter nodes and evidence</label><input id="filter" placeholder="Search node labels, constraints, findings…">
<main><section class="panel"><h2>Control-flow graph</h2><div id="graph" role="img" aria-label="Interactive control-flow graph"></div><p class="muted">Select a node to inspect its details. Graph layout is schematic, not a proof of execution order.</p></section>
<section class="panel"><h2>Selected evidence</h2><pre id="details">Select a graph node or search the full evidence.</pre><h2>Full evidence</h2><pre id="evidence"></pre></section></main>
<script id="pegrex-payload" type="application/json">PAYLOAD</script>
<script>
(function(){
 const payload=JSON.parse(document.getElementById('pegrex-payload').textContent);
 const graph=document.getElementById('graph'), details=document.getElementById('details'), evidence=document.getElementById('evidence');
 const filter=document.getElementById('filter'), status=document.getElementById('graph-status');
 const nodes=Array.isArray(payload.nodes)?payload.nodes:[]; const edges=Array.isArray(payload.edges)?payload.edges:[];
 let selected=null; const ns='http://www.w3.org/2000/svg';
 function element(name,attrs={},text){const e=document.createElementNS(ns,name);for(const [k,v] of Object.entries(attrs))e.setAttribute(k,String(v));if(text!==undefined)e.textContent=String(text);return e;}
 function nodeLabel(n){return String(n.label??n.name??n.id??'node');}
 function visible(n,q){return !q||JSON.stringify(n).toLowerCase().includes(q);}
 function render(){const q=filter.value.trim().toLowerCase();graph.replaceChildren();const visibleNodes=nodes.filter(n=>visible(n,q));const ids=new Set(visibleNodes.map(n=>String(n.id)));
  status.textContent=nodes.length?visibleNodes.length+' / '+nodes.length+' nodes':'No graph nodes supplied';
  if(!visibleNodes.length){graph.textContent='No graph nodes match, or this document contains evidence only.';return;}
  const width=900, rowH=94, nodeW=240, nodeH=58, cols=Math.max(1,Math.min(3,Math.ceil(Math.sqrt(visibleNodes.length))));
  const rows=Math.ceil(visibleNodes.length/cols), height=Math.max(300,rows*rowH+30);const svg=element('svg',{viewBox:`0 0 ${width} ${height}`,role:'group','aria-label':'Control-flow nodes'});
  const pos=new Map();visibleNodes.forEach((n,i)=>pos.set(String(n.id),{x:30+(i%cols)*(width/cols),y:20+Math.floor(i/cols)*rowH}));
  edges.filter(e=>ids.has(String(e.source))&&ids.has(String(e.target))).forEach(e=>{const a=pos.get(String(e.source)),b=pos.get(String(e.target));const x1=a.x+nodeW/2,y1=a.y+nodeH,x2=b.x+nodeW/2,y2=b.y;svg.append(element('path',{d:`M ${x1} ${y1} C ${x1} ${(y1+y2)/2}, ${x2} ${(y1+y2)/2}, ${x2} ${y2}`,class:'edge'}));if(e.label){svg.append(element('text',{x:(x1+x2)/2+4,y:(y1+y2)/2,class:'edge-label'},e.label));}});
  visibleNodes.forEach(n=>{const p=pos.get(String(n.id)),g=element('g',{class:'node'+(String(n.id)===String(selected)?' selected':''),tabindex:0,role:'button','aria-label':nodeLabel(n)});g.append(element('rect',{x:p.x,y:p.y,width:nodeW,height:nodeH,rx:8}));g.append(element('text',{x:p.x+10,y:p.y+21},nodeLabel(n).slice(0,34)));g.append(element('text',{x:p.x+10,y:p.y+42,class:'muted'},String(n.kind??n.type??'node').slice(0,34)));const choose=()=>{selected=n.id;details.textContent=JSON.stringify(n,null,2);render();};g.addEventListener('click',choose);g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();choose();}});svg.append(g);});graph.append(svg);
 }
 filter.addEventListener('input',()=>{render();const q=filter.value.trim().toLowerCase();const text=JSON.stringify(payload,null,2).split('\n').filter(line=>line.toLowerCase().includes(q)).join('\n');evidence.textContent=q?text:JSON.stringify(payload,null,2);});
 evidence.textContent=JSON.stringify(payload,null,2);render();
})();
</script></body></html>'''
    page = page.replace("PAYLOAD", payload)
    dest = Path(output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(page, encoding="utf-8")
    return dest
