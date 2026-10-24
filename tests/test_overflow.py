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


from pegrex.ir import lower_condition
from pegrex.linsolve import atoms_of
from pegrex.overflow import check_overflow

SAFE = atoms_of(lower_condition("x >= 250 and x + 1 <= 255"))
OVER = atoms_of(lower_condition("x >= 255 and x + 1 >= 256"))
T = {"x": "u8"}


def test_in_range_ok_all_modes():
    for m in ("rust_debug", "rust_release", "c", "solidity"):
        assert check_overflow(SAFE, T, m)["x"]["status"] == "ok"


def test_overflow_mode_verdicts():
    v = {m: check_overflow(OVER, T, m)["x"]["status"]
         for m in ("rust_debug", "rust_release", "c", "solidity")}
    assert v == {"rust_debug": "panic-possible", "rust_release": "wraps",
                 "c": "undefined-behavior", "solidity": "revert-possible"}


def test_untyped_refused():
    assert check_overflow(SAFE, {}, "rust_debug")["x"]["status"] == "untracked"


def test_unknown_mode_loud():
    try:
        check_overflow(SAFE, T, "cobol")
        assert False, "ValueError expected"
    except ValueError:
        pass


def test_signed_i8():
    atoms = atoms_of(lower_condition("y >= 100 and y + 100 <= 127"))
    assert check_overflow(atoms, {"y": "i8"}, "rust_debug")["y"]["status"] == "ok"
