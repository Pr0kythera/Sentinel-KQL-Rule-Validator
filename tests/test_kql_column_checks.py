"""
Tests for the .NET-independent logic in KQLValidator: the shared three-way
column-membership outcome (Tasks 5 and 6), the advisory style checks, and schema
merging. These construct the validator via __new__ to avoid loading the Kusto
DLL, so they run without a .NET runtime. The semantic-analysis and
output-column-extraction paths that require .NET are covered separately and skip
when the runtime is unavailable.
"""

from pathlib import Path

from validators.kql_validator import KQLValidator

FILE = Path("rule.yaml")


def make_validator():
    # Bypass __init__ (which loads the DLL); we only exercise pure-Python logic.
    return KQLValidator.__new__(KQLValidator)


def test_match_column_exact():
    assert KQLValidator._match_column("Account", {"Account", "Computer"}) == ("exact", "Account")


def test_match_column_case():
    outcome, correct = KQLValidator._match_column("account", {"Account", "Computer"})
    assert outcome == "case"
    assert correct == "Account"


def test_match_column_missing():
    outcome, correct = KQLValidator._match_column("Nope", {"Account"})
    assert outcome == "missing"
    assert correct is None


def test_membership_exact_passes():
    v = make_validator()
    assert v._column_membership_result("Account", {"Account"}, None, "f", "s") == []


def test_membership_case_is_error_with_correct_case():
    v = make_validator()
    res = v._column_membership_result("account", {"Account"}, None, "f", "s")
    assert len(res) == 1 and res[0]["severity"] == "error"
    assert "Account" in res[0]["message"]


def test_membership_missing_lists_available():
    v = make_validator()
    res = v._column_membership_result("X", {"Account", "Computer"}, None, "f", "s")
    assert res[0]["severity"] == "error"
    assert "Account" in res[0]["message"] and "Computer" in res[0]["message"]


def test_membership_indeterminate_is_warning():
    v = make_validator()
    res = v._column_membership_result("X", set(), "open result type", "f", "s")
    assert res[0]["severity"] == "warning"
    assert "skipped" in res[0]["message"]


def test_entity_columns_casing_error():
    v = make_validator()
    rule = {"entityMappings": [
        {"entityType": "Account",
         "fieldMappings": [{"identifier": "Name", "columnName": "accountname"}]}]}
    res = v._validate_entity_columns(rule, {"AccountName"}, None)
    assert any(r["severity"] == "error" and "AccountName" in r["message"] for r in res)
    assert res[0]["field"] == "entityMappings[0].fieldMappings[0].columnName"


def test_custom_details_columns_missing_error():
    v = make_validator()
    rule = {"customDetails": {"Cmd": "CommandLine"}}
    res = v._validate_custom_details_columns(rule, {"Account"}, None)
    assert res[0]["severity"] == "error"
    assert res[0]["field"] == "customDetails.Cmd"


def test_custom_details_indeterminate_warns():
    v = make_validator()
    rule = {"customDetails": {"Cmd": "CommandLine"}}
    res = v._validate_custom_details_columns(rule, set(), "search used")
    assert res[0]["severity"] == "warning"


def test_query_style_flags_search_and_missing_timegenerated():
    v = make_validator()
    res = v._validate_query_style("search 'evil' | project Account")
    msgs = " ".join(r["message"] for r in res)
    assert "search" in msgs
    assert "TimeGenerated" in msgs


def test_query_style_clean_query_no_warnings():
    v = make_validator()
    res = v._validate_query_style("SecurityEvent | where TimeGenerated > ago(1d) | project Account")
    assert res == []


def test_merge_schema_override_adds_table():
    base = {"database": "SecurityInsights", "tables": {"A": {"columns": {"x": "string"}}}}
    override = {"tables": {"B": {"columns": {"y": "int"}}}}
    merged = KQLValidator._merge_schema(base, override)
    assert "A" in merged["tables"] and "B" in merged["tables"]
