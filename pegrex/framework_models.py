"""Versioned security framework models for the conservative Python taint engine.

Models are declarative: adding a signature does not claim coverage for dynamic
calls, reflection, framework magic, or unsupported language constructs.
"""
from __future__ import annotations
from .flow import SourceRule, SinkRule

MODEL_VERSION = "pegrex-framework-models.v2"

# Explicit common framework sources. Patterns match dotted call names exactly.
FRAMEWORK_SOURCES = (
    SourceRule("flask-request-accessor", r"(?:flask\.)?request\.(?:args|form|json|values|headers|cookies|files)", kind="attribute", category="user-input"),
    SourceRule("flask-request-get", r"(?:flask\.)?request\.(?:args|form|values|headers|cookies)\.get", category="user-input"),
    SourceRule("flask-request-json", r"(?:flask\.)?request\.(?:get_json|json)", category="user-input"),
    SourceRule("django-request-accessor", r"request\.(?:GET|POST|body|FILES|COOKIES|META|headers)", kind="attribute", category="user-input"),
    SourceRule("django-request-get", r"request\.(?:GET|POST|headers)\.get", category="user-input"),
    SourceRule("fastapi-query", r"(?:Query|Path|Header|Cookie|Form|File|Body)", category="user-input"),
    SourceRule("environment-read", r"(?:os\.)?(?:getenv|environ\.get)", category="configuration"),
    SourceRule("environment-config", r"(?:config|settings)\.(?:get|read)", category="configuration"),
)

FRAMEWORK_SINKS = (
    SinkRule("ssrf-http-client", r"(?:requests|httpx|urllib\.request)\.(?:get|post|put|patch|delete|request|urlopen)", category="ssrf", severity="HIGH", message="untrusted data may reach an outbound request target", arguments=(0, 1, 2), sanitizers=(r"validate_url|allowlisted_url|is_allowed_url",)),
    SinkRule("path-traversal-file", r"(?:open|pathlib\.Path|os\.open|os\.remove|os\.unlink|shutil\.(?:copy|move))", category="path-traversal", severity="HIGH", message="untrusted data may reach a filesystem path", arguments=(0, 1), sanitizers=(r"resolve_within|safe_join|validate_path|path_is_within",)),
    SinkRule("command-injection-process", r"(?:os\.system|os\.popen|subprocess\.(?:run|Popen|call|check_output|check_call))", category="command-injection", severity="HIGH", message="untrusted data may reach a process invocation", arguments=(0, 1), sanitizers=(r"shlex\.quote|validated_argv|subprocess\.list2cmdline",)),
    SinkRule("unsafe-deserialization", r"(?:pickle\.(?:loads|load)|yaml\.load|marshal\.loads|dill\.(?:loads|load))", category="unsafe-deserialization", severity="HIGH", message="untrusted data may reach an unsafe deserializer", arguments=(0,), sanitizers=(r"yaml\.safe_load|validated_payload",)),
    SinkRule("template-injection", r"(?:jinja2\.Template|Template|render_template_string|Environment\.from_string)", category="template-injection", severity="HIGH", message="untrusted data may be interpreted as a template", arguments=(0,), sanitizers=(r"escape_template|trusted_template",)),
    SinkRule("dynamic-sql", r"(?:[A-Za-z_]\w*\.)*(?:execute|executemany|raw)", category="sql-injection", severity="HIGH", message="untrusted data may reach a query execution API", arguments=(0,), sanitizers=(r"parameterized_query|sql_identifier",)),
)


def combined_models():
    """Return immutable model tuples suitable for analyze_source/analyze_modules."""
    return FRAMEWORK_SOURCES, FRAMEWORK_SINKS
