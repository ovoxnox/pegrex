#!/usr/bin/env python3
"""Collect PegRex self-analysis artifacts without executing analyzed source."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import traceback

ROOT = Path('/mnt/agents/output/pegrex_audit/source/pegrex')
OUT = Path('/mnt/agents/output/pegrex_audit/self_artifacts')
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

STEPS = []


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                               default=str) + '\n', encoding='utf-8')


def step(name, function):
    print(f'[{len(STEPS)+1}] {name}', flush=True)
    try:
        value = function()
        STEPS.append({'name': name, 'status': 'ok'})
        return value
    except Exception as error:
        STEPS.append({'name': name, 'status': 'unknown',
                      'error': f'{type(error).__name__}: {error}',
                      'traceback': traceback.format_exc()})
        write_json(OUT / 'errors' / f'{name}.json', {
            'status': 'unknown', 'artifact': name,
            'error': f'{type(error).__name__}: {error}'})
        print(f'  UNKNOWN: {type(error).__name__}: {error}', flush=True)
        return None


def copy_reports():
    for source, target in [
        ('docs/SELF.md', 'reports/SELF.md'),
        ('docs/HEALTH.md', 'reports/HEALTH.md'),
        ('docs/ARCHITECTURE.md', 'reports/ARCHITECTURE.md'),
        ('docs/PUBLIC_CONTRACTS.md', 'reports/PUBLIC_CONTRACTS.md'),
        ('VALIDATION.md', 'reports/VALIDATION.md'),
        ('specs/pegrex_health.spec.json', 'specs/pegrex_health.spec.json'),
        ('specs/pegrex_health.dispositions.json', 'specs/pegrex_health.dispositions.json'),
    ]:
        destination = OUT / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / source, destination)


def repository_artifacts():
    from pegrex.repository import RepositoryIndex
    from pegrex.repomemory import RepositoryMemory
    from pegrex.semgraph import SemanticDependencyGraph
    from pegrex.contextcompiler import compile_agent_context
    analysis_root = ROOT / 'pegrex' / 'core'
    index = RepositoryIndex(analysis_root, max_paths=200, timeout_ms=1000)
    report = index.scan()
    write_json(OUT / 'repository' / 'index-report.json', report)
    index.save(OUT / 'repository' / 'index-state.json')
    memory = RepositoryMemory(analysis_root)
    memory.index = index
    memory.refresh()
    memory.save(OUT / 'repository' / 'memory.json')
    graph = SemanticDependencyGraph(memory)
    refresh = graph.refresh()
    graph.save(OUT / 'graphs' / 'semantic-dependencies.json')
    write_json(OUT / 'graphs' / 'semantic-refresh.json', refresh)
    context = compile_agent_context(memory, max_characters=250000)
    write_json(OUT / 'repository' / 'agent-context.json', context)
    return memory


def rag_artifacts():
    from pegrex.rag import build_index
    from pegrex.hybridrag import HybridRetriever
    index = build_index([ROOT / 'pegrex', ROOT / 'tools', ROOT / 'tests',
                         ROOT / 'pipeline.py', ROOT / 'service.py'])
    rag = OUT / 'rag'
    rag.mkdir(parents=True, exist_ok=True)
    with (rag / 'chunks.jsonl').open('w', encoding='utf-8') as stream:
        for number, chunk in enumerate(index.chunks):
            source = Path(chunk.source).resolve()
            try:
                source_name = source.relative_to(ROOT).as_posix()
            except ValueError:
                source_name = str(source)
            row = {'id': number, 'source': source_name,
                   'start_line': chunk.start_line, 'text': chunk.text,
                   'token_count': len(chunk.tokens)}
            stream.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + '\n')
    inverted = {json.dumps(token, ensure_ascii=False): sorted(rows)
                for token, rows in sorted(index.inverted.items(),
                                          key=lambda row: repr(row[0]))}
    write_json(rag / 'index.json', {
        'schema': 'pegrex.self-rag-index.v1', 'chunks': len(index.chunks),
        'terms': len(inverted), 'doc_len': index.doc_len,
        'retriever': 'HybridRetriever (BM25 + local embeddings)',
        'chunking': 'function-aware with line-window fallback'})
    write_json(rag / 'inverted-index.json', inverted)
    documents = [chunk.text for chunk in index.chunks]
    retriever = HybridRetriever(documents)
    queries = [
        'workspace confinement symlink path validation',
        'three valued proved refuted unknown path contracts',
        'release evidence provenance SHA-256 manifest',
        'restricted AST evaluation without exec',
        'repository memory semantic dependency graph',
        'coverage gaps test synthesis',
    ]
    results = []
    for query in queries:
        hits = []
        for hit in retriever.search(query, k=8):
            chunk = index.chunks[hit['doc']]
            hits.append({'chunk': hit['doc'],
                         'source': str(Path(chunk.source).resolve().relative_to(ROOT)),
                         'start_line': chunk.start_line,
                         'score': hit.get('score'), 'text': chunk.text})
        results.append({'query': query, 'hits': hits})
    write_json(rag / 'example-retrievals.json', results)


def call_and_fact_graphs():
    from pegrex.twin import build, cognitive_report
    from pegrex.facts import collect_facts
    from pegrex.graph import build_graph
    engine = ROOT / 'pegrex'
    twin = build(str(engine))
    portable = dict(twin)
    portable['files'] = {name: str(Path(path).relative_to(ROOT))
                         for name, path in twin['files'].items()}
    portable['root'] = 'pegrex'
    write_json(OUT / 'graphs' / 'call-twin.json', portable)
    dot = ['digraph pegrex_calls {', '  rankdir=LR;']
    for name in sorted(twin['functions']):
        dot.append(f'  {json.dumps(name)};')
    for caller, callees in sorted(twin['calls'].items()):
        for callee in callees:
            dot.append(f'  {json.dumps(caller)} -> {json.dumps(callee)};')
    dot.append('}')
    (OUT / 'graphs' / 'callgraph.dot').write_text('\n'.join(dot) + '\n', encoding='utf-8')
    facts = {}
    fact_edges = []
    for path in sorted(engine.rglob('*.py')):
        relative = path.relative_to(ROOT).as_posix()
        try:
            row = collect_facts(path.read_text(encoding='utf-8'))
            facts[relative] = row
            fact_edges.extend(('calls', f'{relative}:{a}', f'{relative}:{b}')
                              for a, b in row['calls'])
        except Exception as error:
            facts[relative] = {'status': 'unknown',
                               'error': f'{type(error).__name__}: {error}'}
    write_json(OUT / 'graphs' / 'facts.json', facts)
    twin_edges = [('reaches', caller, callee)
                  for caller, callees in twin['calls'].items() for callee in callees]
    unified = build_graph(fact_edges=fact_edges, twin_edges=twin_edges,
                          owners=twin['owners'])
    write_json(OUT / 'graphs' / 'unified-graph.json', unified)
    write_json(OUT / 'reports' / 'cognitive-twin.json', cognitive_report(twin))


def digital_twin():
    memory = json.loads((OUT / 'repository' / 'memory.json').read_text(encoding='utf-8'))
    semantic = json.loads((OUT / 'graphs' / 'semantic-dependencies.json').read_text(encoding='utf-8'))
    calls = json.loads((OUT / 'graphs' / 'call-twin.json').read_text(encoding='utf-8'))
    unknown_contracts = sorted(key for key, row in memory['apis'].items()
                               if row['status'] != 'ok' or row['unknowns'])
    unowned = sorted(name for name in calls['functions'] if not calls['owners'].get(name))
    payload = {'schema': 'pegrex.repository-digital-twin.v1', 'schema_version': 1,
               'root_name': ROOT.name,
               'call_graph': {'functions': calls['functions'], 'calls': calls['calls'],
                              'files': calls['files']},
               'ownership': calls['owners'], 'repository_memory': memory,
               'contract_dependency_graph': semantic, 'change_history': [],
               'risk_exposure': {'declared': [],
                                 'unknown_contract_functions': unknown_contracts,
                                 'unowned_functions': unowned},
               'unknowns': sorted(set(memory['limitations'] + ['change history not supplied'])),
               'scope': 'indexed static graphs and supplied history/risk evidence; unseen runtime paths remain possible'}
    payload['twin_identity'] = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    write_json(OUT / 'repository' / 'digital-twin.json', payload)


def architecture_index():
    from tools.repokit import repo_index
    report = repo_index(str(ROOT / 'pegrex'), str(OUT / 'repository' / 'architecture-index.json'))
    return report


def supply_chain():
    from pegrex.sbom import generate_sbom
    from pegrex.sca import scan, snapshot_provenance
    lockfile = ROOT / 'requirements-ci.txt'
    write_json(OUT / 'supply-chain' / 'sbom.cyclonedx.json',
               generate_sbom(str(lockfile), format='cyclonedx'))
    write_json(OUT / 'supply-chain' / 'sbom.spdx.json',
               generate_sbom(str(lockfile), format='spdx'))
    write_json(OUT / 'supply-chain' / 'osv-provenance.json', snapshot_provenance())
    write_json(OUT / 'supply-chain' / 'sca-offline.json',
               scan(str(lockfile), offline=True))


def verification_bundles():
    from tools.repokit import verification_bundle
    selected = ['pegrex/difforacle.py', 'pegrex/loopsum.py', 'pegrex/constraints.py',
                'pegrex/semanticchecksum.py', 'pegrex/core/contracts.py']
    summary = []
    for name in selected:
        target = OUT / 'verification-bundles' / (name.replace('/', '__') + '.json')
        try:
            bundle = verification_bundle(str(ROOT / name), str(target))
            summary.append({'source': name, 'status': 'ok',
                            'paths': len(bundle['paths']), 'artifact': target.name})
        except Exception as error:
            summary.append({'source': name, 'status': 'unknown',
                            'error': f'{type(error).__name__}: {error}'})
    write_json(OUT / 'verification-bundles' / 'index.json', summary)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    step('copy-generated-reports', copy_reports)
    step('repository-memory-and-context', repository_artifacts)
    step('rag-index-and-retrievals', rag_artifacts)
    step('call-fact-and-unified-graphs', call_and_fact_graphs)
    step('digital-twin', digital_twin)
    step('architecture-index', architecture_index)
    step('supply-chain-evidence', supply_chain)
    step('verification-bundles', verification_bundles)
    write_json(OUT / 'generation-report.json', {
        'schema': 'pegrex.self-analysis-generation.v1',
        'source_root': ROOT.name, 'steps': STEPS,
        'unknown_steps': [row['name'] for row in STEPS if row['status'] != 'ok']})
    print(json.dumps({'steps': len(STEPS),
                      'unknown': [row['name'] for row in STEPS if row['status'] != 'ok']}, indent=2))


if __name__ == '__main__':
    main()
