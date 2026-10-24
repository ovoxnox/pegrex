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


from pegrex.sqlrel import Table, equivalent, parse_select

ORM = Table("users").filter(age__gt=5).filter(age__lt=10).values("name", "age")


def test_equivalent_reordered():
    r = equivalent("SELECT age, name FROM users WHERE age < 10 AND age > 5", ORM)
    assert r["equivalent"] is True


def test_weaker_filter_refused():
    r = equivalent("SELECT name, age FROM users WHERE age > 5", ORM)
    assert r["equivalent"] is False
    assert r["orm_implies_sql"] is True and r["sql_implies_orm"] is False


def test_table_mismatch():
    r = equivalent("SELECT name, age FROM accounts WHERE age > 5 AND age < 10", ORM)
    assert r["equivalent"] is False and "table" in r["reason"]


def test_vacuous_refused():
    r = equivalent("SELECT name, age FROM users WHERE age > 50 AND age < 3", ORM)
    assert r["equivalent"] is False and "vacuous" in r["reason"]


def test_malformed_refused():
    with pytest.raises((ValueError, Exception)):
        parse_select("DELETE FROM users")


def test_orm_record_matches_sql_record():
    rec = Table("t").filter(x__gte=1).values("x")
    assert rec["where"] == parse_select("SELECT x FROM t WHERE x >= 1")["where"]
