import pytest

from switchboard import ontology, text2sql
from switchboard.text2sql import SQLRejected, validate


@pytest.mark.parametrize("sql", [
    "SELECT name FROM canon_customer",                          # PII column not exposed
    "SELECT * FROM legacy.wln_cfg",                              # raw legacy / secret table
    "SELECT psk_enc FROM wln_cfg",
    "DELETE FROM canon_customer",
    "SELECT 1; DROP TABLE sub_mstr",
    "SELECT load_extension('x') FROM canon_customer",
    "SELECT customer_id FROM canon_customer UNION SELECT cpe_sn FROM canon_resource",
    "SELECT customer_id AS name, name FROM canon_customer",     # alias shadowing a PII column
    "SELECT customer_id name",                                  # found by Hypothesis fuzzing
])
def test_validator_rejects(sql):
    with pytest.raises(SQLRejected):
        validate(sql)


def test_validator_enforces_limit():
    assert "LIMIT 200" in validate("SELECT customer_id FROM canon_customer")
    assert "LIMIT 200" in validate("SELECT customer_id FROM canon_customer LIMIT 100000")


def test_scope_fail_closed():
    assert text2sql.answer("how many customers in 02139", scope_subscribers=[])["rows"][0]["n"] == 0


def test_canon_view_dedupes_migration_duplicates():
    r = text2sql.answer("how many customers in 02139", scope_subscribers=None)
    assert r["rows"][0]["n"] == 24  # S-58123 duplicate collapsed


def test_inclusion_dependency_profiler_finds_implicit_fk():
    deps = {(a, b) for a, b, _ in text2sql.profile_inclusion_deps()}
    assert ("cpe_inv.sbscr_ref", "sub_mstr.sbscr_id") in deps


def test_generated_grants_exclude_secret_and_pii():
    g = " ".join(ontology.grants_sql())
    assert "psk_enc" not in g and "nm_txt" not in g and "sbscr_id" in g
