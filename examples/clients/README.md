# Service clients

`python service.py` speaks JSON-lines on stdin/stdout:

- `ping` -> `{pong: true}`
- `parse` `{language, source}` -> pegrex Node tree as JSON
  (`language`: `python` | `go` | `rust` via real tree-sitter, `c` via pegrex)
- `contracts` `{language, source}` -> function contract (c only)
- `verify` `{spec}` -> runs a spec, issues the certificate

## go_client.go -- VERIFIED END-TO-END

Compiled with Go 1.23.4 (`go build`, stdlib only, offline) and run against
the live service: sends a `parse` request for Python source, receives the
JSON AST, prints `ast tag: module`. Regression test:
`tests/test_go_client.py`.

## rust_client.rs

Same protocol in Rust (requires serde_json from crates.io; if the registry
is unreachable, the protocol is already validated by the Go client and
`tests/test_service.py` -- serde_json adds only decoding convenience).
