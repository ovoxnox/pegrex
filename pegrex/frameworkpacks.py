"""Versioned taint source/sink packs for common framework boundaries."""
from __future__ import annotations
from .flow import SourceRule, SinkRule, DEFAULT_SOURCES, analyze_source
SCHEMA = "pegrex.taint-framework-packs.v1"


def _packs():
    return {
      "web": ((
        SourceRule("web-request-name", r"(?:request|req)(?:\..*)?", kind="name", category="untrusted", pack="web"),
        SourceRule("web-request-data", r"(?:flask\.)?request\.(?:args|form|json|data|files).*", kind="name", category="untrusted", pack="web"),
        SourceRule("web-header", r".*(?:header|cookie|query).*", kind="name", category="untrusted", pack="web")), (
        SinkRule("web-redirect", r"(?:flask\.)?redirect", category="open-redirect", pack="web"),)),
      "database": ((), (
        SinkRule("database-query", r".*(?:execute|executemany|executescript|raw_sql|raw)", category="sql-injection", pack="database"),)),
      "shell": ((), (
        SinkRule("shell-process", r"(?:os\.)?system|subprocess\.(?:run|Popen|call|check_output)", category="process-execution", sanitizers=(r"shlex\.quote", r"validate(?:d)?"), pack="shell"),)),
      "deserialization": ((), (
        SinkRule("unsafe-deserialization", r"(?:pickle|cPickle|marshal)\.(?:load|loads)|yaml\.(?:load|unsafe_load)", category="unsafe-deserialization", pack="deserialization"),)),
      "templating": ((), (
        SinkRule("template-injection", r".*(?:render_template_string|from_string|Template)", category="template-injection", pack="templating"),)),
      "cloud": ((
        SourceRule("cloud-secret", r".*(?:secretsmanager|ssm|vault).*(?:get|read).*", category="configuration-secret", pack="cloud"),), (
        SinkRule("cloud-egress", r".*(?:boto3|s3|sns|sqs|requests|httpx).*(?:put|post|send|upload|publish|request).*", category="network-egress", pack="cloud"),)),
    }


def framework_packs(names=()) -> dict:
    """Implement framework packs with the module's explicit API and failure semantics."""
    available = _packs()
    selected = tuple(names) or tuple(sorted(available))
    unknown = sorted(set(selected) - set(available))
    sources, sinks, provenance = list(DEFAULT_SOURCES), [], []
    for name in sorted(set(selected) & set(available)):
        source, sink = available[name]
        sources.extend(source); sinks.extend(sink)
        provenance.append({"pack": name, "version": 1,
                           "source_rules": [row.id for row in source],
                           "sink_rules": [row.id for row in sink]})
    sources = list(dict.fromkeys(sources)); sinks = list(dict.fromkeys(sinks))
    return {"schema": SCHEMA, "schema_version": 1, "source_rules": sources,
            "sink_rules": sinks, "packs": provenance,
            "unknowns": [f"unknown framework pack: {name}" for name in unknown]}


def analyze_with_frameworks(source, names=(), *, path="<memory>.py") -> dict:
    """Implement analyze with frameworks with the module's explicit API and failure semantics."""
    packs = framework_packs(names)
    report = analyze_source(source, path=path, source_rules=packs["source_rules"],
                            sink_rules=packs["sink_rules"], report_parameters=False)
    identities = {row.id: row.pack for row in packs["source_rules"] + packs["sink_rules"]}
    for finding in report["findings"]:
        finding["rule_pack"] = identities.get(finding["id"], "core")
    report["rule_packs"] = packs["packs"]
    report["unknowns"] = sorted(set(report["unknowns"] + packs["unknowns"]))
    return report
