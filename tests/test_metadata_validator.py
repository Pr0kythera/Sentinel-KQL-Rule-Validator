"""Tests for MetadataValidator (Task 4)."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

from validators.metadata_validator import MetadataValidator

FILE = Path("rule.yaml")


def v():
    return MetadataValidator()


def _fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _past(days):
    return _fmt(datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days))


def _future(days):
    return _fmt(datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=days))


# -- author ---------------------------------------------------------------

def test_valid_author_passes():
    assert v()._validate_author({"author": "contact.prokythera@gmail.com"}) == []


def test_invalid_author_errors():
    res = v()._validate_author({"author": "not-an-email"})
    assert res and res[0]["severity"] == "error"


def test_empty_author_errors():
    assert v()._validate_author({"author": "  "})[0]["severity"] == "error"


# -- creationDate ---------------------------------------------------------

def test_creation_date_bad_format_errors():
    errs, dt = v()._validate_creation_date({"creationDate": "2026-07-07 12:00:00"})
    assert errs and dt is None


def test_creation_date_future_errors():
    errs, dt = v()._validate_creation_date({"creationDate": _future(2)})
    assert any("future" in e["message"] for e in errs)


def test_creation_date_valid_returns_datetime():
    errs, dt = v()._validate_creation_date({"creationDate": _past(10)})
    assert errs == [] and isinstance(dt, datetime)


# -- reviewDate -----------------------------------------------------------

def test_review_date_too_soon_errors():
    creation = datetime(2026, 1, 1, 0, 0, 0)
    res = v()._validate_review_date({"reviewDate": "2026-06-01T00:00:00"}, creation)
    assert any("at least one year" in e["message"] for e in res)


def test_review_date_one_year_ok():
    creation = datetime(2026, 1, 1, 0, 0, 0)
    # 400 days ahead and in the future -> no error, no overdue warning
    future_review = _future(400)
    res = v()._validate_review_date({"reviewDate": future_review}, creation)
    assert all(e["severity"] != "error" for e in res)


def test_review_date_overdue_warns():
    creation = datetime(2000, 1, 1, 0, 0, 0)
    res = v()._validate_review_date({"reviewDate": _past(5)}, creation)
    assert any(e["severity"] == "warning" and "overdue" in e["message"] for e in res)


# -- environment ----------------------------------------------------------

def test_environment_non_empty_ok():
    assert v()._validate_environment({"environment": "Production"}) == []


def test_environment_empty_errors():
    assert v()._validate_environment({"environment": ""})[0]["severity"] == "error"


def test_environment_allowlist_rejects_unknown():
    mv = MetadataValidator(environment_allowlist=["Production", "Staging"])
    res = mv._validate_environment({"environment": "Prod"})
    assert res and res[0]["severity"] == "error"


# -- tables ---------------------------------------------------------------

def test_tables_duplicates_error():
    res = v()._validate_tables({"tables": ["SecurityEvent", "SecurityEvent"], "query": "x"})
    assert any("more than once" in e["message"] for e in res)


def test_tables_empty_list_errors():
    res = v()._validate_tables({"tables": []})
    assert any("must not be empty" in e["message"] for e in res)


def test_tables_non_string_entry_errors():
    res = v()._validate_tables({"tables": [123], "query": ""})
    assert any(e["severity"] == "error" for e in res)


def test_tables_unreferenced_warns():
    rule = {"tables": ["SecurityEvent"], "query": "SigninLogs | project X"}
    res = v()._validate_tables(rule)
    assert any(e["severity"] == "warning" and "not referenced" in e["message"] for e in res)


def test_tables_referenced_no_warning():
    rule = {"tables": ["SecurityEvent"], "query": "SecurityEvent | project X"}
    res = v()._validate_tables(rule)
    assert all("not referenced" not in e["message"] for e in res)
