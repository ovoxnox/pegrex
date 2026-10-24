try:
    import pytest
except ImportError:
    class _Raises:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, t, v, tb):
            assert t is not None and issubclass(t, self.exc), f"expected {self.exc}"
            return True
    class _PytestShim:
        @staticmethod
        def raises(exc): return _Raises(exc)
    pytest = _PytestShim()

import pathlib

from pegrex.compress import compress_context, validate_compression

TARGET = str(pathlib.Path(__file__).resolve().parent.parent /
             "examples" / "fixtures" / "codepaths.py")


def test_payload_smaller():
    assert compress_context(TARGET)["payload_bytes"] < compress_context(TARGET)["source_bytes"]


def test_lossless_findings():
    assert validate_compression(TARGET)["lossless"]


def test_has_contracts_and_findings():
    c = compress_context(TARGET)
    assert c["contracts"] and c["finding_ids"]
