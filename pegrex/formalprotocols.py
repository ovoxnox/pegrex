"""Strict parser adapters for data/configuration formats; parsing is not semantic proof."""
from __future__ import annotations

import configparser
import csv
import hashlib
import io
import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SCHEMA = "pegrex.formal-protocol.v1"


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _json_schema(value, schema, path="$"):
    if not isinstance(schema, dict):
        raise ValueError("JSON schema subset must be an object")
    expected = schema.get("type")
    types = {"object": dict, "array": list, "string": str, "boolean": bool,
             "integer": int, "number": (int, float), "null": type(None)}
    if expected:
        if expected not in types:
            raise ValueError(f"unsupported JSON schema type: {expected}")
        if not isinstance(value, types[expected]) or (expected in {"integer", "number"} and isinstance(value, bool)):
            raise ValueError(f"{path} does not have schema type {expected}")
    if expected == "object":
        for name in schema.get("required", []):
            if name not in value:
                raise ValueError(f"{path} is missing required property {name}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            unexpected = sorted(set(value) - set(properties))
            if unexpected:
                raise ValueError(f"{path} has additional properties: {unexpected}")
        for name, child in properties.items():
            if name in value:
                _json_schema(value[name], child, path + "." + name)
    if expected == "array" and "items" in schema:
        for index, item in enumerate(value):
            _json_schema(item, schema["items"], f"{path}[{index}]")


class _SExpressionParser:
    def __init__(self, text):
        self.text, self.position = text, 0

    def _space(self):
        while self.position < len(self.text):
            if self.text[self.position].isspace():
                self.position += 1
            elif self.text[self.position] == ";":
                end = self.text.find("\n", self.position)
                self.position = len(self.text) if end < 0 else end + 1
            else:
                break

    def parse(self):
        """Implement parse with the module's explicit API and failure semantics."""
        self._space()
        if self.position >= len(self.text):
            raise ValueError("empty S-expression")
        value = self._value()
        self._space()
        if self.position != len(self.text):
            raise ValueError("trailing S-expression input")
        return value

    def _value(self):
        self._space()
        if self.position >= len(self.text):
            raise ValueError("unexpected end of S-expression")
        character = self.text[self.position]
        if character == "(":
            self.position += 1
            values = []
            while True:
                self._space()
                if self.position >= len(self.text):
                    raise ValueError("unclosed S-expression list")
                if self.text[self.position] == ")":
                    self.position += 1
                    return values
                values.append(self._value())
        if character == ")":
            raise ValueError("unexpected closing parenthesis")
        if character == '"':
            return self._string()
        start = self.position
        while self.position < len(self.text) and not self.text[self.position].isspace() and self.text[self.position] not in "();":
            self.position += 1
        if start == self.position:
            raise ValueError("empty atom")
        return self.text[start:self.position]

    def _string(self):
        self.position += 1
        value = []
        while self.position < len(self.text):
            character = self.text[self.position]
            self.position += 1
            if character == '"':
                return "".join(value)
            if character == "\\":
                if self.position >= len(self.text):
                    raise ValueError("unclosed string escape")
                escape = self.text[self.position]
                self.position += 1
                translations = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
                if escape not in translations:
                    raise ValueError(f"unsupported string escape: {escape}")
                value.append(translations[escape])
            else:
                value.append(character)
        raise ValueError("unclosed string")


def _canonical_sexp(value):
    if isinstance(value, list):
        return "(" + " ".join(_canonical_sexp(row) for row in value) + ")"
    if any(character.isspace() or character in '();"\\' for character in value) or not value:
        return json.dumps(value, ensure_ascii=False)
    return value


def _parse(format, text, options, schema):
    if format == "json":
        value = json.loads(text, object_pairs_hook=_json_object)
        if schema is not None:
            _json_schema(value, schema)
        return value, json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False), "json-duplicate-rejecting-stdlib"
    if format == "url":
        parsed = urlsplit(text)
        if any(character.isspace() for character in text):
            raise ValueError("URL contains unescaped whitespace")
        position = 0
        while position < len(text):
            if text[position] == "%":
                if position + 2 >= len(text) or any(character not in "0123456789abcdefABCDEF"
                                                     for character in text[position + 1:position + 3]):
                    raise ValueError("URL contains an invalid percent escape")
                position += 3
            else:
                position += 1
        if not parsed.scheme and not options.get("allow_relative"):
            raise ValueError("absolute URL scheme required")
        if parsed.scheme and not parsed.netloc and parsed.scheme in {"http", "https", "ftp"}:
            raise ValueError("hierarchical URL authority required")
        port = parsed.port
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        canonical = urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path,
                                urlencode(query, doseq=True), parsed.fragment))
        return {"scheme": parsed.scheme, "netloc": parsed.netloc, "path": parsed.path,
                "query": query, "fragment": parsed.fragment, "port": port}, canonical, "urllib.parse-strict-query"
    if format == "csv":
        delimiter = options.get("delimiter", ",")
        quotechar = options.get("quotechar", '"')
        if len(delimiter) != 1 or len(quotechar) != 1:
            raise ValueError("CSV delimiter and quote character must be one character")
        rows = list(csv.reader(io.StringIO(text, newline=""), delimiter=delimiter,
                               quotechar=quotechar, strict=True))
        if rows and any(len(row) != len(rows[0]) for row in rows):
            raise ValueError("CSV rows have inconsistent widths")
        return rows, json.dumps(rows, ensure_ascii=False, separators=(",", ":")), "stdlib csv strict"
    if format == "ini":
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read_string(text)
        value = {section: dict(parser.items(section)) for section in parser.sections()}
        return value, json.dumps(value, sort_keys=True, separators=(",", ":")), "configparser strict no-interpolation"
    if format in {"sexp", "s-expression"}:
        value = _SExpressionParser(text).parse()
        return value, _canonical_sexp(value), "recursive-descent-sexp-v1"
    if format in {"properties", "config"}:
        value = {}
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("#", "!")):
                continue
            separator = "=" if "=" in line else ":" if ":" in line else None
            if separator is None:
                raise ValueError(f"configuration line {number} has no key/value separator")
            key, item = (part.strip() for part in line.split(separator, 1))
            if not key or key in value:
                raise ValueError(f"empty or duplicate configuration key on line {number}")
            value[key] = item
        return value, json.dumps(value, sort_keys=True, separators=(",", ":")), "strict-properties-v1"
    raise ValueError(f"unsupported protocol format: {format}")


def parse_protocol(text, *, format, options=None, schema=None) -> dict:
    """Parse one complete document with a named strict grammar adapter."""
    format = format.lower()
    try:
        value, canonical, grammar = _parse(format, text, options or {}, schema)
        return {"schema": SCHEMA, "schema_version": 1, "format": format,
                "grammar": grammar, "verdict": "proved", "status": "parsed",
                "value": value, "canonical": canonical,
                "canonical_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                "unknowns": [], "scope": "well-formedness and declared schema only"}
    except (ValueError, TypeError, csv.Error, configparser.Error, json.JSONDecodeError) as error:
        return {"schema": SCHEMA, "schema_version": 1, "format": format,
                "verdict": "unknown", "status": "unknown", "value": None,
                "canonical": None, "unknowns": [f"protocol parse failed: {type(error).__name__}: {error}"]}
