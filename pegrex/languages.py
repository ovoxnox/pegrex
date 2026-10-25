"""Single source of truth for language identity, parser routing and capabilities.

A registered parser does not automatically imply contract extraction or proof
support. Consumers must ask this registry which operation is available. The
registry imports heavyweight parser bindings lazily to keep minimal installs
usable and to avoid import cycles with pipeline.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any
import platform


@dataclass(frozen=True)
class LanguageSpec:
    name: str
    extensions: tuple[str, ...]
    parser: str
    capabilities: frozenset[str]
    aliases: tuple[str, ...] = ()
    binding: tuple[str, str] | None = None
    comment_prefix: str | None = None
    contract_mode: str | None = None
    frontend_factory: str | None = None
    notes: str = ""
    parse_adapter: str = "tree-sitter"
    parser_language: str | None = None
    rule_inherits: tuple[str, ...] = ()
    contract_handler: str | None = None
    tag_spec: str | None = None
    function_tag: str | None = None
    outcome_renderer: str = "strip-return"
    parser_version: str = "unspecified"
    source_coordinates: str = "python-char"
    normalizer: str = "unspecified"
    error_policy: str = "raise"
    cfg_adapter: str | None = None
    supported_constructs: tuple[str, ...] = ()
    expression_lowering: str = "unsupported"
    contract_features: tuple[str, ...] = ()
    security_rule_packs: tuple[str, ...] = ()
    maturity: str = "experimental"
    known_unsupported: tuple[str, ...] = ()


_TS_COORDINATES = "utf8-byte-input->python-char-normalized"
_TS_NORMALIZER = "tree-sitter.named->pegrex.Node"
_ERROR_UNKNOWN = "raise; scanner converts parser failure to PEGREX-PARSER-UNKNOWN"
_PATTERN_PACK = "audit:secrules.json"
_TAINT_PACK = "taint:secrules_taint.json"
_CFG_FEATURES = ("path-constraints", "outcomes", "entrypoint-selection")
_TS_CFG = "tree_sitter_bridge.TagSpec->CFGBuilder"
_TS_LOWERING = "typed-ir; comparisons; boolean and/or; opaque bare variables"

_SPECS = (
    LanguageSpec(
        "python", (".py", ".pyw"), "tree-sitter-or-stdlib",
        frozenset({"parse", "contracts", "audit", "taint", "callgraph", "effects", "summaries", "semantic-diff"}),
        aliases=("py",), binding=("tree_sitter_python", "language"), comment_prefix="#",
        contract_mode="pipeline", frontend_factory="python_frontend",
        function_tag="function_definition", outcome_renderer="strip-return",
        parser_version="tree-sitter-python>=0.25,<0.26; stdlib fallback",
        source_coordinates=_TS_COORDINATES, normalizer=_TS_NORMALIZER,
        error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("if/elif/else", "while", "for", "try", "return", "break", "continue", "match", "with"),
        expression_lowering=_TS_LOWERING,
        contract_features=_CFG_FEATURES + ("call-summary-expansion", "cross-variant-equivalence"),
        security_rule_packs=(_PATTERN_PACK, _TAINT_PACK), maturity="stable",
        known_unsupported=("unbounded loops require explicit unroll limits", "no whole-program or field-sensitive proof")),
    LanguageSpec(
        "go", (".go",), "tree-sitter",
        frozenset({"parse", "contracts", "audit", "taint", "callgraph", "semantic-diff"}),
        binding=("tree_sitter_go", "language"), comment_prefix="//",
        contract_mode="tree-sitter", frontend_factory="go_frontend", function_tag="function_declaration",
        parser_version="tree-sitter-go>=0.25,<0.26", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("if/else", "for", "return", "break"),
        expression_lowering=_TS_LOWERING, contract_features=_CFG_FEATURES,
        security_rule_packs=(_PATTERN_PACK, _TAINT_PACK), maturity="experimental",
        known_unsupported=("goroutines and channel interleaving", "defer/panic control flow", "whole-program proof")),
    LanguageSpec(
        "rust", (".rs",), "tree-sitter",
        frozenset({"parse", "contracts", "audit", "taint", "callgraph", "semantic-diff"}),
        binding=("tree_sitter_rust", "language"), comment_prefix="//",
        contract_mode="tree-sitter", frontend_factory="rust_frontend", function_tag="function_item",
        parser_version="tree-sitter-rust>=0.24,<0.25", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("if/else", "while", "return", "break", "match", "tail expressions"),
        expression_lowering=_TS_LOWERING, contract_features=_CFG_FEATURES,
        security_rule_packs=(_PATTERN_PACK, _TAINT_PACK), maturity="experimental",
        known_unsupported=("borrow/lifetime verification", "unsafe concurrency semantics", "macro expansion")),
    LanguageSpec(
        "javascript", (".js", ".jsx", ".mjs", ".cjs"), "tree-sitter",
        frozenset({"parse", "contracts", "audit", "taint", "callgraph", "semantic-diff"}),
        binding=("tree_sitter_javascript", "language"), aliases=("js", "jsx"), comment_prefix="//",
        contract_mode="tree-sitter", frontend_factory="javascript_frontend", function_tag="function_declaration",
        parser_version="tree-sitter-javascript>=0.25,<0.26", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("if/else", "while", "for", "return", "break", "continue", "with"),
        expression_lowering=_TS_LOWERING, contract_features=_CFG_FEATURES,
        security_rule_packs=(_PATTERN_PACK, _TAINT_PACK), maturity="experimental",
        known_unsupported=("async/event-loop semantics", "prototype and dynamic-property semantics", "exceptions as proof-covered control flow")),
    LanguageSpec(
        "typescript", (".ts", ".mts", ".cts"), "tree-sitter",
        frozenset({"parse", "contracts", "audit", "semantic-diff"}),
        binding=("tree_sitter_typescript", "language_typescript"), aliases=("ts",), comment_prefix="//",
        contract_mode="tree-sitter", frontend_factory="typescript_frontend", rule_inherits=("javascript",),
        tag_spec="javascript", function_tag="function_declaration",
        parser_version="optional tree-sitter-typescript/language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("JavaScript CFG subset",), expression_lowering=_TS_LOWERING,
        contract_features=_CFG_FEATURES, security_rule_packs=(_PATTERN_PACK,), maturity="experimental",
        known_unsupported=("type-level verification", "TSX syntax in the TypeScript parser", "dedicated taint rules")),
    LanguageSpec(
        "tsx", (".tsx",), "tree-sitter", frozenset({"parse", "audit"}),
        binding=("tree_sitter_typescript", "language_tsx"), comment_prefix="//",
        notes="Parsing and audit only; no dedicated contract frontend.", rule_inherits=("javascript",),
        tag_spec="javascript", parser_version="optional tree-sitter-typescript/language-pack",
        source_coordinates=_TS_COORDINATES, normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN,
        security_rule_packs=(_PATTERN_PACK,), maturity="parse-only",
        known_unsupported=("contracts", "CFG construction", "expression lowering", "taint")),
    LanguageSpec(
        "solidity", (".sol",), "tree-sitter",
        frozenset({"parse", "contracts", "audit", "semantic-diff"}),
        binding=("tree_sitter_solidity", "language"), comment_prefix="//",
        contract_mode="tree-sitter", frontend_factory="solidity_frontend", function_tag="function_definition",
        parser_version="optional tree-sitter-solidity/language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("if/else", "while", "for", "return", "break"),
        expression_lowering=_TS_LOWERING, contract_features=_CFG_FEATURES,
        security_rule_packs=(_PATTERN_PACK,), maturity="experimental",
        known_unsupported=("EVM cross-call and reentrancy semantics", "blockchain environment proof", "delegatecall storage semantics")),
    LanguageSpec(
        "julia", (".jl",), "tree-sitter",
        frozenset({"parse", "contracts", "audit", "semantic-diff"}),
        binding=("tree_sitter_julia", "language"), comment_prefix="#",
        contract_mode="tree-sitter", frontend_factory="julia_frontend", function_tag="function_definition",
        parser_version="optional tree-sitter-julia/language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("if/else", "while", "for", "return", "break"),
        expression_lowering=_TS_LOWERING, contract_features=_CFG_FEATURES,
        security_rule_packs=(_PATTERN_PACK,), maturity="experimental",
        known_unsupported=("multiple dispatch", "metaprogramming", "full numeric promotion semantics")),
    LanguageSpec(
        "kotlin", (".kt", ".kts"), "tree-sitter",
        frozenset({"parse", "contracts", "audit", "semantic-diff"}),
        binding=("tree_sitter_kotlin", "language"), comment_prefix="//",
        contract_mode="tree-sitter", frontend_factory="kotlin_frontend", function_tag="function_declaration",
        parser_version="optional tree-sitter-kotlin/language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("if/else", "while", "for", "return", "break"),
        expression_lowering=_TS_LOWERING, contract_features=_CFG_FEATURES,
        security_rule_packs=(_PATTERN_PACK,), maturity="experimental",
        known_unsupported=("coroutines", "nullability/type-system proof", "JVM interoperability semantics")),
    LanguageSpec(
        "zig", (".zig",), "tree-sitter", frozenset({"parse", "contracts", "semantic-diff"}),
        binding=("tree_sitter_zig", "language"), comment_prefix="//",
        contract_mode="tree-sitter", frontend_factory="zig_frontend", function_tag="function_declaration",
        parser_version="optional tree-sitter-zig/language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, cfg_adapter=_TS_CFG,
        supported_constructs=("if/else", "while", "for", "return", "break"),
        expression_lowering=_TS_LOWERING, contract_features=_CFG_FEATURES,
        maturity="experimental", known_unsupported=("comptime execution", "error unions", "security rule pack")),
    LanguageSpec(
        "c", (".c", ".h"), "peg-grammar",
        frozenset({"parse", "contracts", "audit", "cognitive", "semantic-diff"}),
        aliases=("c11",), comment_prefix="//", contract_mode="pipeline", frontend_factory="c_frontend",
        notes="Contract extraction uses the bundled C grammar.", parse_adapter="c-peg", outcome_renderer="c",
        parser_version="bundled c11.gram", normalizer="c-peg->pegrex.Node",
        error_policy=_ERROR_UNKNOWN, cfg_adapter="pipeline.c_frontend.TagSpec->CFGBuilder",
        supported_constructs=("C11 grammar subset", "if/else", "loops", "return"),
        expression_lowering="integer constants; identifiers; comparisons",
        contract_features=_CFG_FEATURES + ("call-summary-expansion", "cross-variant-equivalence"),
        security_rule_packs=(_PATTERN_PACK,), maturity="stable",
        known_unsupported=("full C preprocessor semantics", "pointer/alias proof", "undefined-behavior model")),
    LanguageSpec(
        "cpp", (".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"), "tree-sitter-language-pack",
        frozenset({"parse", "audit"}), aliases=("c++",), comment_prefix="//",
        notes="Parse/audit support only; distinct from C.", parser_version="optional tree-sitter-language-pack",
        source_coordinates=_TS_COORDINATES, normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN,
        security_rule_packs=(_PATTERN_PACK,), maturity="parse-only",
        known_unsupported=("C++ contract extraction", "templates", "CFG construction", "expression lowering")),
    LanguageSpec(
        "lua", (".lua",), "tree-sitter-language-pack", frozenset({"parse"}), comment_prefix="--",
        notes="Parsing only in the public registry; service rendering helpers are not a complete CFG frontend.",
        parser_version="optional tree-sitter-language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, maturity="parse-only",
        known_unsupported=("public contract extraction", "CFG construction", "expression lowering", "security audit")),
    LanguageSpec(
        "vyper", (".vy",), "tree-sitter-language-pack", frozenset({"parse", "audit"}), comment_prefix="#",
        notes="Vyper is not routed through Solidity semantics.", parser_version="optional tree-sitter-language-pack",
        source_coordinates=_TS_COORDINATES, normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN,
        security_rule_packs=(_PATTERN_PACK,), maturity="parse-only",
        known_unsupported=("contracts", "CFG construction", "Solidity semantic reuse", "taint")),
    LanguageSpec(
        "cobol", (".cob", ".cbl", ".cobol"), "native-mock",
        frozenset({"parse", "contracts", "semantic-diff", "legacy-modernization"}), comment_prefix="*> ",
        contract_mode="native", notes="Native contract frontend plus offline tree-sitter mock.",
        contract_handler="cobolfront.contracts", parser_version="bundled native parser/mock",
        source_coordinates=_TS_COORDINATES, normalizer="cobol-native/mock->pegrex.Node",
        error_policy=_ERROR_UNKNOWN, cfg_adapter="cobolfront.native-contracts",
        supported_constructs=("paragraphs", "PERFORM", "conditions", "arithmetic"),
        expression_lowering="COBOL condition and arithmetic subset",
        contract_features=("path-constraints", "outcomes", "cross-language-equivalence", "legacy-modernization"),
        maturity="stable", known_unsupported=("full COPY preprocessor semantics", "file I/O and runtime environment proof", "security rule packs")),
    LanguageSpec(
        "fortran", (".f", ".for", ".f90", ".f95", ".f03", ".f08"), "native-mock",
        frozenset({"parse", "contracts", "semantic-diff", "legacy-modernization"}), comment_prefix="!",
        contract_mode="native", notes="Native contract frontend plus offline tree-sitter mock.",
        contract_handler="fortranfront.contracts", parser_version="bundled native parser/mock",
        source_coordinates=_TS_COORDINATES, normalizer="fortran-native/mock->pegrex.Node",
        error_policy=_ERROR_UNKNOWN, cfg_adapter="fortranfront.native-contracts",
        supported_constructs=("functions/subroutines", "IF", "DO", "assignments"),
        expression_lowering="Fortran condition and arithmetic subset",
        contract_features=("path-constraints", "outcomes", "cross-language-equivalence", "legacy-modernization"),
        maturity="stable", known_unsupported=("full COMMON/EQUIVALENCE memory model", "I/O and intrinsics proof", "security rule packs")),
    LanguageSpec(
        "sql", (".sql",), "domain-specific", frozenset({"sql-relations"}),
        notes="Only the documented SQL subset is analyzed; generic CST parsing is not exposed.",
        parser_version="bundled SQL subset", normalizer="sqlrel-subset", error_policy="raise; unsupported queries refuse",
        cfg_adapter="sqlrel", supported_constructs=("SELECT subset", "OR groups"),
        expression_lowering="relational predicates in the documented subset",
        contract_features=("SQL/ORM-equivalence", "sampled-equivalence-with-sample-size"), maturity="domain-specific",
        known_unsupported=("generic CST parsing", "unlisted SQL syntax", "proof from sampling alone")),
    LanguageSpec(
        "circom", (".circom",), "domain-specific", frozenset({"zk-audit"}),
        notes="Circuit analysis is subset-based; generic CST parsing is not exposed.",
        parser_version="bundled Circom subset", normalizer="zk-subset", error_policy="raise; unsupported circuits refuse",
        cfg_adapter="zk-audit", supported_constructs=("signals", "constraints", "templates in the documented subset"),
        expression_lowering="circuit-constraint subset", contract_features=("under-constrained-signal-audit",),
        maturity="domain-specific", known_unsupported=("generic CST parsing", "full Circom compiler semantics", "functional-correctness proof")),
    LanguageSpec(
        "csharp", (".cs",), "tree-sitter-language-pack", frozenset({"parse"}), comment_prefix="//",
        parser_version="optional tree-sitter-language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, maturity="parse-only",
        known_unsupported=("contracts", "CFG construction", "expression lowering", "security audit")),
    LanguageSpec(
        "java", (".java",), "tree-sitter-language-pack", frozenset({"parse"}), comment_prefix="//",
        parser_version="optional tree-sitter-language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, maturity="parse-only",
        known_unsupported=("contracts", "CFG construction", "expression lowering", "security audit")),
    LanguageSpec(
        "ruby", (".rb",), "tree-sitter-language-pack", frozenset({"parse"}), comment_prefix="#",
        parser_version="optional tree-sitter-language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, maturity="parse-only",
        known_unsupported=("contracts", "CFG construction", "expression lowering", "security audit")),
    LanguageSpec(
        "php", (".php",), "tree-sitter-language-pack", frozenset({"parse"}), comment_prefix="//",
        parser_version="optional tree-sitter-language-pack", source_coordinates=_TS_COORDINATES,
        normalizer=_TS_NORMALIZER, error_policy=_ERROR_UNKNOWN, maturity="parse-only",
        known_unsupported=("contracts", "CFG construction", "expression lowering", "security audit")),
)

LANGUAGES: dict[str, LanguageSpec] = {spec.name: spec for spec in _SPECS}
ALIASES: dict[str, str] = {
    alias: spec.name for spec in _SPECS for alias in spec.aliases
}
EXTENSION_MAP: dict[str, str] = {
    ext.lower(): spec.name for spec in _SPECS for ext in spec.extensions
}


def normalize_language(language: str | None) -> str | None:
    if language is None:
        return None
    name = str(language).strip().lower()
    name = ALIASES.get(name, name)
    return name if name in LANGUAGES else None


def get_language(language: str) -> LanguageSpec:
    normalized = normalize_language(language)
    if normalized is None:
        raise ValueError(f"unsupported language {language!r}; known languages: {', '.join(sorted(LANGUAGES))}")
    return LANGUAGES[normalized]


def detect_language(path: str | Path, explicit: str | None = None, *, default: str | None = None) -> str | None:
    """Resolve explicit name first, then suffix, then optional default."""
    if explicit is not None:
        normalized = normalize_language(explicit)
        if normalized is None:
            raise ValueError(f"unsupported explicit language {explicit!r}")
        return normalized
    spec = EXTENSION_MAP.get(Path(path).suffix.lower())
    if spec:
        return spec
    return normalize_language(default) if default else None


def language_capabilities(language: str) -> dict[str, Any]:
    spec = get_language(language)
    return {
        "language": spec.name,
        "extensions": list(spec.extensions),
        "parser": spec.parser,
        "capabilities": sorted(spec.capabilities),
        "contract_mode": spec.contract_mode,
        "frontend_factory": spec.frontend_factory,
        "comment_prefix": spec.comment_prefix,
        "notes": spec.notes,
        "parse_adapter": spec.parse_adapter,
        "parser_language": spec.parser_language or spec.name,
        "rule_inherits": list(spec.rule_inherits),
        "contract_handler": spec.contract_handler,
        "tag_spec": spec.tag_spec or spec.name,
        "function_tag": spec.function_tag,
        "outcome_renderer": spec.outcome_renderer,
    }


def capability_matrix() -> list[dict[str, Any]]:
    """Legacy capability view; use :func:`plugin_registry` for full metadata."""
    return [language_capabilities(name) for name in sorted(LANGUAGES)]


def frontend_manifest(language: str) -> dict[str, Any]:
    """Return the canonical declarative frontend plugin manifest."""
    spec = get_language(language)
    return {
        "language": spec.name,
        "extensions": list(spec.extensions),
        "aliases": list(spec.aliases),
        "parser": {
            "implementation": spec.parser,
            "version": spec.parser_version,
            "adapter": spec.parse_adapter,
            "binding": ({"module": spec.binding[0], "attribute": spec.binding[1]}
                        if spec.binding else None),
            "parser_language": spec.parser_language or spec.name,
        },
        "source_coordinates": spec.source_coordinates,
        "normalizer": spec.normalizer,
        "error_policy": spec.error_policy,
        "cfg": {
            "adapter": spec.cfg_adapter,
            "supported_constructs": list(spec.supported_constructs),
        },
        "expression_lowering": spec.expression_lowering,
        "contracts": {
            "mode": spec.contract_mode,
            "features": list(spec.contract_features),
            "handler": spec.contract_handler or spec.frontend_factory,
            "outcome_renderer": spec.outcome_renderer,
        },
        "security_rule_packs": list(security_rule_packs(spec.name)),
        "capabilities": sorted(spec.capabilities),
        "maturity": spec.maturity,
        "known_unsupported": list(spec.known_unsupported),
        "notes": spec.notes,
    }


def parser_provenance(language: str, *, used: str | None = None) -> dict[str, Any]:
    """Record declared and actually installed parser versions for reproducibility."""
    spec = get_language(language)
    distributions = {"tree-sitter"}
    if spec.binding:
        distributions.add(spec.binding[0].replace("_", "-"))
    installed, unavailable = {}, []
    for distribution in sorted(distributions):
        try:
            installed[distribution] = importlib_metadata.version(distribution)
        except importlib_metadata.PackageNotFoundError:
            unavailable.append(distribution)
    result = {
        "language": spec.name,
        "implementation": spec.parser,
        "adapter": spec.parse_adapter,
        "declared_version": spec.parser_version,
        "used": used or ("unavailable" if spec.binding and spec.binding[0].replace("_", "-") in unavailable
                         else spec.parse_adapter),
        "installed_versions": installed,
        "unavailable_distributions": unavailable,
        "python": platform.python_version(),
    }
    if spec.parse_adapter == "c-peg":
        import hashlib
        grammar = Path(__file__).resolve().parent.parent / "examples" / "c11.gram"
        if grammar.exists():
            result["grammar_sha256"] = hashlib.sha256(grammar.read_bytes()).hexdigest()
    return result


def plugin_registry() -> list[dict[str, Any]]:
    """Machine-readable canonical registry, sorted for deterministic output."""
    return [frontend_manifest(name) for name in sorted(LANGUAGES)]


def soundness_report(language: str | None = None) -> dict[str, Any]:
    """Expose the trust policy and per-plugin limits without claiming completeness."""
    plugins = ([frontend_manifest(language)] if language is not None
               else plugin_registry())
    return {
        "schema": "pegrex.soundness.v1",
        "policy": {
            "verdicts": ["proved", "refuted", "unknown"],
            "parser_availability": "does not imply contract, audit, or proof support",
            "contract_identity": "(constraints, outcome), including source and function identity where available",
            "coordinates": "public source spans are zero-based, end-exclusive Python character offsets",
            "unsupported_analysis": "refuse or return unknown; never infer safety from missing evidence",
            "incomplete_security_scan": "emit kind=unknown coverage findings; --fail-on-unknown turns them into exit 2",
            "counterexamples": "only confirmed witnesses justify refuted",
            "completion": "pipeline or process completion alone is not an independent proof",
        },
        "plugins": plugins,
    }


def security_rule_packs(language: str | None = None, *,
                        capability: str | None = None) -> tuple[str, ...]:
    """Resolve rule packs from plugins and declared inheritance, never a second map."""
    if (language is not None and capability is not None
            and capability not in get_language(language).capabilities):
        return ()
    names = LANGUAGES.values() if language is None else (
        LANGUAGES[name] for name in rule_languages(language))
    allowed = ({capability} if capability is not None else
               ({"audit", "taint"} if language is None else
                {name for name in ("audit", "taint")
                 if name in get_language(language).capabilities}))
    packs = set()
    for spec in names:
        for declaration in spec.security_rule_packs:
            kind, separator, path = declaration.partition(":")
            if not separator or not path:
                raise RuntimeError(f"invalid rule pack declaration for {spec.name}: {declaration!r}")
            if kind in allowed:
                packs.add(path)
    return tuple(sorted(packs))


def supports(language: str, capability: str) -> bool:
    return capability in get_language(language).capabilities


def frontend_registry() -> dict[str, str]:
    """Authoritative mapping of languages to CFG/path-contract factories."""
    return {spec.name: spec.frontend_factory for spec in _SPECS
            if "contracts" in spec.capabilities and spec.frontend_factory}

def validate_registry() -> list[str]:
    """Return consistency errors; an empty list means dispatch metadata is coherent."""
    errors: list[str] = []
    seen_extensions: dict[str, str] = {}
    seen_aliases: dict[str, str] = {}
    for spec in _SPECS:
        for extension in spec.extensions:
            ext = extension.lower()
            prior = seen_extensions.get(ext)
            if prior and prior != spec.name:
                errors.append(f"extension {ext!r} maps to both {prior} and {spec.name}")
            seen_extensions[ext] = spec.name
        for alias in spec.aliases:
            prior = seen_aliases.get(alias.lower())
            if prior and prior != spec.name:
                errors.append(f"alias {alias!r} maps to both {prior} and {spec.name}")
            seen_aliases[alias.lower()] = spec.name
        if "contracts" in spec.capabilities:
            if spec.contract_mode not in {"native", "tree-sitter", "pipeline"}:
                errors.append(f"{spec.name}: contracts capability has no supported contract mode")
            if spec.contract_mode == "pipeline" and not spec.frontend_factory:
                errors.append(f"{spec.name}: pipeline contracts missing frontend_factory")
            if spec.contract_mode == "native" and not spec.contract_handler:
                errors.append(f"{spec.name}: native contracts missing contract_handler")
        if "parse" in spec.capabilities and spec.parse_adapter not in _PARSE_ADAPTERS:
            errors.append(f"{spec.name}: unknown parse adapter {spec.parse_adapter!r}")
        for capability in spec.capabilities:
            if not capability or capability != capability.strip():
                errors.append(f"{spec.name}: invalid capability {capability!r}")
        if spec.parser_version == "unspecified" or spec.normalizer == "unspecified":
            errors.append(f"{spec.name}: incomplete parser/normalizer plugin metadata")
        if spec.maturity not in {"stable", "experimental", "parse-only", "domain-specific"}:
            errors.append(f"{spec.name}: invalid maturity {spec.maturity!r}")
        if spec.source_coordinates not in {"python-char", _TS_COORDINATES}:
            errors.append(f"{spec.name}: unknown source coordinate convention")
        if "contracts" in spec.capabilities:
            if not spec.cfg_adapter or not spec.supported_constructs:
                errors.append(f"{spec.name}: contract plugin missing CFG adapter/construct metadata")
            if spec.expression_lowering == "unsupported" or not spec.contract_features:
                errors.append(f"{spec.name}: contract plugin missing lowering/feature metadata")
        if "audit" in spec.capabilities and _PATTERN_PACK not in spec.security_rule_packs:
            errors.append(f"{spec.name}: audit plugin missing pattern rule pack")
        if "taint" in spec.capabilities and _TAINT_PACK not in spec.security_rule_packs:
            errors.append(f"{spec.name}: taint plugin missing taint rule pack")
        if not spec.known_unsupported:
            errors.append(f"{spec.name}: known unsupported cases must be explicit")
    return errors


def load_tree_sitter_parser(language: str):
    """Load the parser selected by registry metadata, with lazy optional deps."""
    spec = get_language(language)
    if "parse" not in spec.capabilities:
        raise NotImplementedError(f"parsing is not registered for {spec.name}: {spec.notes}")
    if spec.parser == "native-mock":
        from . import tsmock
        return tsmock.get_parser(spec.name)
    if spec.parser in {"peg-grammar", "domain-specific"}:
        raise NotImplementedError(
            f"{spec.name} uses the {spec.parser} adapter, not a Tree-sitter parser")

    try:
        from tree_sitter import Language, Parser
    except ImportError as exc:
        raise ImportError("Tree-sitter parsing requires `pip install pegrex[parsers]`") from exc

    if spec.binding:
        module_name, attribute = spec.binding
        try:
            module = __import__(module_name)
            return Parser(Language(getattr(module, attribute)()))
        except (ImportError, AttributeError, TypeError):
            # Prefer the registered binding, but keep an explicit pack fallback.
            pass
    try:
        from tree_sitter_language_pack import get_parser
        return get_parser(spec.parser_language or spec.name)
    except ImportError as exc:
        raise ImportError(
            f"no parser binding installed for {spec.name!r}; install `pegrex[parsers]`") from exc
    except Exception as exc:
        raise ValueError(f"no parser available for registered language {spec.name!r}: {exc}") from exc


def _parse_treesitter(spec: LanguageSpec, source: str):
    # Local import keeps parser bindings out of the stable registry's import path.
    from .tree_sitter_bridge import parse_tree_sitter
    return parse_tree_sitter(spec.name, source)


def _parse_c_peg(spec: LanguageSpec, source: str):
    from pathlib import Path
    import sys
    root = str(Path(__file__).resolve().parent.parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    import pipeline
    return pipeline.c_parse_full(source)


_PARSE_ADAPTERS = {
    "tree-sitter": _parse_treesitter,
    "c-peg": _parse_c_peg,
}


def parse_source(language: str, source: str):
    """Parse full source via the single registry-selected parser adapter."""
    spec = get_language(language)
    if "parse" not in spec.capabilities:
        raise NotImplementedError(f"parsing is not registered for {spec.name}: {spec.notes}")
    adapter = _PARSE_ADAPTERS.get(spec.parse_adapter)
    if adapter is None:
        raise RuntimeError(
            f"registered parse adapter {spec.parse_adapter!r} for {spec.name} is missing")
    return adapter(spec, source)


def get_contract_frontend(language: str):
    """Resolve a contract frontend via registry metadata; parse-only languages refuse."""
    spec = get_language(language)
    if "contracts" not in spec.capabilities or not spec.frontend_factory:
        raise NotImplementedError(
            f"contract extraction is not supported for {spec.name}: {spec.notes}")
    import pipeline
    factory = getattr(pipeline, spec.frontend_factory, None)
    if not callable(factory):
        raise RuntimeError(
            f"registered frontend {spec.frontend_factory!r} for {spec.name} is missing")
    return factory


def extract_contract_pairs(language: str, source: str, *, entrypoint: str | None = None,
                           tree=None, max_paths: int | None = None,
                           timeout_ms: int | None = None):
    """Dispatch contract extraction solely by registered contract mode.

    Returns the legacy sequence of ``(guards, outcome)`` pairs so extraction
    algorithms remain replaceable; normalization and public result semantics
    belong to :mod:`pegrex.core`.
    """
    spec = get_language(language)

    def limited(rows):
        if max_paths is not None and len(rows) > max_paths:
            from .paths import PathExplosion
            raise PathExplosion(f"path count cap {max_paths} exceeded")
        return rows

    if "contracts" not in spec.capabilities:
        raise NotImplementedError(
            f"contract extraction is not supported for {spec.name}: {spec.notes}")
    if spec.contract_mode == "native":
        if not spec.contract_handler:
            raise RuntimeError(f"native contract handler missing for registered language {spec.name}")
        from importlib import import_module
        module = import_module(f".{spec.contract_handler.split('.', 1)[0]}", package=__package__)
        handler = getattr(module, spec.contract_handler.split('.', 1)[1], None)
        if not callable(handler):
            raise RuntimeError(f"registered contract handler {spec.contract_handler!r} is missing")
        return limited(handler(source))
    if spec.contract_mode == "tree-sitter":
        from .tscontracts import contracts
        return limited(contracts(source, spec.name, tree=tree))
    if spec.contract_mode == "pipeline":
        parse, tag_spec, make_cond = get_contract_frontend(spec.name)()
        body = parse(source, entrypoint, tree=tree) if entrypoint is not None else parse(source, tree=tree)
        from .cfg import CFGBuilder
        from .summaries import path_summaries, render_c
        if spec.outcome_renderer == "c":
            render = lambda statement: render_c(statement, source)
        else:
            def render(statement, _source=source, _mode=spec.outcome_renderer):
                if statement.children and isinstance(statement.children[0], str):
                    text = statement.children[0]
                else:
                    text = _source[statement.pos:statement.endpos]
                if _mode == "strip-return":
                    return text.replace("return", "", 1).strip()
                return text.strip()
        cfg = CFGBuilder(tag_spec).build(body)
        if max_paths is not None:
            from .paths import PathExplosion
            from .summaries import path_summaries_bounded
            result = path_summaries_bounded(cfg, make_cond(source), render,
                                            max_paths=max_paths, timeout_ms=timeout_ms)
            if not result["complete"]:
                raise PathExplosion("; ".join(result["unknowns"]))
            return result["contracts"]
        return path_summaries(cfg, make_cond(source), render)
    raise RuntimeError(
        f"unsupported registered contract mode {spec.contract_mode!r} for {spec.name}")


def rule_languages(language: str) -> frozenset[str]:
    """Return this language plus registry-declared compatible rule languages."""
    spec = get_language(language)
    result = {spec.name}
    pending = list(spec.rule_inherits)
    while pending:
        candidate = pending.pop()
        normalized = normalize_language(candidate)
        if normalized is None or normalized in result:
            continue
        result.add(normalized)
        pending.extend(LANGUAGES[normalized].rule_inherits)
    return frozenset(result)
