import json
import pytest

from pegrex.compilerir import parse_compiler_ir
from pegrex.formalprotocols import parse_protocol
from pegrex.modernization import modernize_preserving_contracts
from pegrex.roundtrip import check_round_trip
from pegrex.smartcontract import analyze_smart_contract, check_evm_bytecode

COBOL = """       IDENTIFICATION DIVISION.
       PROGRAM-ID. ABSVAL.
       *> pegrex: result RES
       PROCEDURE DIVISION.
           IF N >= 0 THEN
               MOVE N TO RES
           ELSE
               COMPUTE RES = 0 - N
           END-IF.
           GOBACK.
"""

FORTRAN = """function absval(n)
  if (n >= 0) then
    absval = n
  else
    absval = -n
  end if
end function
"""

SPEC = {"openapi": "3.0.0", "paths": {"/add": {"post": {
    "operationId": "add",
    "parameters": [{"name": "a", "required": True, "schema": {"type": "integer"}},
                   {"name": "b", "required": True, "schema": {"type": "integer"}}],
    "responses": {"200": {"content": {"application/json": {"schema": {"type": "integer"}}}}},
}}}}
PY_SERVER = "def add(a: int, b: int) -> int:\n    return a + b\n"
GO_CLIENT = "func add(a int, b int) int {\n    return a + b\n}\n"


def test_cobol_python_modernization_proves_contract_and_declared_numeric_scope(tmp_path):
    source = tmp_path / "abs.cob"
    source.write_text(COBOL)
    result = modernize_preserving_contracts(source, "python",
        numeric={"bits": 0, "signed": True, "overflow": "unbounded"}, layout=[])
    assert result["verdict"] == "proved" and result["verified"]
    assert result["contract_evidence"]["verdict"] == "proved"
    namespace = {}
    exec(result["code"], namespace)
    assert namespace["absval"](-7) == 7


def test_fortran_go_round_trip_and_rust_overflow_remain_distinct(tmp_path):
    pytest.importorskip("tree_sitter", reason="cross-language modernization needs optional parser dependencies")
    source = tmp_path / "abs.f90"
    source.write_text(FORTRAN)
    go = modernize_preserving_contracts(source, "go",
        numeric={"bits": 64, "signed": True, "overflow": "wrap"}, layout=[])
    assert go["verdict"] == "proved"
    assert go["code"].count("if ") == 2 and "else" not in go["code"]

    rust = modernize_preserving_contracts(source, "rust",
        numeric={"bits": 64, "signed": True, "overflow": "trap"}, layout=[])
    assert rust["contract_evidence"]["verdict"] == "proved"
    assert rust["verdict"] == "unknown" and not rust["verified"]
    assert "build profile" in rust["unknowns"][0]


def test_modernization_requires_numeric_and_nonoverlapping_layout_evidence(tmp_path):
    source = tmp_path / "abs.cob"
    source.write_text(COBOL)
    missing = modernize_preserving_contracts(source, "python")
    assert missing["verdict"] == "unknown"
    overlap = modernize_preserving_contracts(source, "python",
        numeric={"bits": 0, "signed": True, "overflow": "unbounded"},
        layout=[{"name": "a", "offset": 0, "size": 4},
                {"name": "b", "offset": 2, "size": 4}])
    assert overlap["verdict"] == "refuted"
    assert "overlapping fields" in overlap["layout_evidence"]["reason"]


def test_old_new_api_round_trip_includes_generated_stubs_and_runtime_cases():
    invoker = lambda operation, params: params["a"] + params["b"]
    result = check_round_trip(SPEC,
        old_server=PY_SERVER, new_server=PY_SERVER,
        old_client=GO_CLIENT, new_client=GO_CLIENT,
        old_invoker=invoker, new_invoker=invoker,
        cases=[{"operation": "add", "params": {"a": 2, "b": 3}}])
    assert result["verdict"] == "proved" and result["compatible"]
    assert result["static_drift"] == []
    assert "def add" in result["generated_stubs"]["python_server"]
    assert "func add" in result["generated_stubs"]["go_client"]


def test_static_api_agreement_without_runtime_is_unknown_and_mismatch_refutes():
    static = check_round_trip(SPEC)
    assert static["verdict"] == "unknown" and not static["compatible"]
    changed = check_round_trip(SPEC,
        old_invoker=lambda operation, params: params["a"] + params["b"],
        new_invoker=lambda operation, params: params["a"] - params["b"],
        cases=[{"operation": "add", "params": {"a": 2, "b": 3}}])
    assert changed["verdict"] == "refuted"


def test_smart_contract_layers_do_not_substitute_for_each_other():
    runner = lambda bytecode, tests: {"executed": True, "local": True,
        "backend": "local-evm-test", "results": [{"passed": True} for _ in tests]}
    result = analyze_smart_contract(
        source="contract C { function f() public { tx.origin; } }",
        bytecode="60ff",
        formal_claims=[{"id": "safety", "verdict": "proved"}],
        local_tests=[{"name": "smoke"}], evm_runner=runner)
    assert result["sections"]["source"]["verdict"] == "refuted"
    assert result["sections"]["bytecode"]["findings"] == []  # FF is PUSH data.
    assert result["sections"]["formal"]["verdict"] == "unknown"  # Missing proof.
    assert result["sections"]["local_evm"]["verdict"] == "proved"
    assert result["verdict"] == "refuted"


def test_bytecode_disassembly_and_local_evm_failure_are_explicit():
    bytecode = check_evm_bytecode("610fff00ff")
    assert [row["id"] for row in bytecode["findings"]] == ["EVM-SELFDESTRUCT"]
    result = analyze_smart_contract(bytecode="ff", local_tests=[{"name": "fail"}],
        evm_runner=lambda code, tests: {"executed": True, "local": True,
                                        "results": [{"passed": False}]})
    assert result["sections"]["local_evm"]["verdict"] == "refuted"
    unavailable = analyze_smart_contract(bytecode="ff", local_tests=[{"name": "x"}])
    assert unavailable["sections"]["local_evm"]["verdict"] == "unknown"


def test_json_url_csv_ini_sexp_and_properties_strict_adapters():
    parsed = parse_protocol('{"a":1,"items":[true]}', format="json", schema={
        "type": "object", "required": ["a"],
        "properties": {"a": {"type": "integer"}, "items": {"type": "array", "items": {"type": "boolean"}}},
        "additionalProperties": False})
    assert parsed["verdict"] == "proved"
    assert parse_protocol('{"a":1,"a":2}', format="json")["verdict"] == "unknown"

    url = parse_protocol("HTTPS://example.test/a?q=hello+world&empty=", format="url")
    assert url["verdict"] == "proved" and url["value"]["query"][1] == ("empty", "")
    assert parse_protocol("https://example.test/%ZZ", format="url")["verdict"] == "unknown"

    assert parse_protocol('a,b\n1,"x,y"\n', format="csv")["value"] == [["a", "b"], ["1", "x,y"]]
    assert parse_protocol("a,b\n1\n", format="csv")["verdict"] == "unknown"
    assert parse_protocol("[s]\na=1\n", format="ini")["value"] == {"s": {"a": "1"}}
    assert parse_protocol("[s]\na=1\na=2\n", format="ini")["verdict"] == "unknown"

    sexp = parse_protocol('(define (f "x y") ; comment\n (f "x y"))', format="sexp")
    assert sexp["verdict"] == "proved" and sexp["canonical"].startswith("(define")
    assert parse_protocol("(open", format="sexp")["verdict"] == "unknown"
    assert parse_protocol("b=2\na: 1\n", format="properties")["canonical"] == '{"a":"1","b":"2"}'
    assert parse_protocol("a=1\na=2\n", format="properties")["verdict"] == "unknown"


def test_llvm_mir_mlir_versioned_control_flow_parsers():
    llvm = parse_compiler_ir("""define i32 @f(i1 %c) {
entry:
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 0
}
""", format="llvm", version="17")
    assert llvm["verdict"] == "proved"
    assert len(llvm["functions"][0]["edges"]) == 2

    mir = parse_compiler_ir("""bb0: {
  _1 = const 1;
  goto -> bb1;
}
bb1: {
  return;
}
""", format="mir", version="rust-1")
    assert mir["verdict"] == "proved"
    assert mir["functions"][0]["edges"][0]["target"] == "bb1"

    mlir = parse_compiler_ir("""func.func @f(%c: i1) {
^entry:
  cf.cond_br %c, ^yes, ^no
^yes:
  func.return
^no:
  func.return
}
""", format="mlir", version="1")
    assert mlir["verdict"] == "proved"
    assert len(mlir["functions"][0]["edges"]) == 2


def test_ir_unsupported_terminator_and_version_cannot_be_proof_mode_graphs():
    unsupported = parse_compiler_ir("""define void @f() {
entry:
  switch i32 0, label %default [ i32 0, label %other ]
default:
  ret void
other:
  ret void
}
""", format="llvm", version="18", proof_mode=True)
    assert unsupported["verdict"] == "unknown"
    assert parse_compiler_ir("bb0: {\n return;\n}\n", format="mir", version="unknown")["verdict"] == "unknown"
