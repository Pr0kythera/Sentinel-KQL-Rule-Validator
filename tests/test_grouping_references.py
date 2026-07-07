"""Tests for group-by consistency (Task 7)."""

from pathlib import Path

from validators.sentinel_constraints_validator import SentinelConstraintsValidator

FILE = Path("rule.yaml")


def check(rule):
    return SentinelConstraintsValidator()._validate_grouping_references(rule)


def test_groupby_custom_detail_unknown_key_errors():
    rule = {
        "customDetails": {"Cmd": "CommandLine"},
        "incidentConfiguration": {"groupingConfiguration": {
            "groupByCustomDetails": ["NotDefined"]}},
    }
    res = check(rule)
    assert any(r["severity"] == "error" and "NotDefined" in r["message"] for r in res)


def test_groupby_custom_detail_known_key_ok():
    rule = {
        "customDetails": {"Cmd": "CommandLine"},
        "incidentConfiguration": {"groupingConfiguration": {
            "groupByCustomDetails": ["Cmd"]}},
    }
    assert check(rule) == []


def test_groupby_entities_unknown_type_errors():
    rule = {
        "entityMappings": [{"entityType": "Account", "fieldMappings": []}],
        "incidentConfiguration": {"groupingConfiguration": {
            "groupByEntities": ["Host"]}},
    }
    res = check(rule)
    assert any(r["severity"] == "error" and "Host" in r["message"] for r in res)


def test_groupby_entities_known_type_ok():
    rule = {
        "entityMappings": [{"entityType": "Account", "fieldMappings": []}],
        "incidentConfiguration": {"groupingConfiguration": {
            "groupByEntities": ["Account"]}},
    }
    assert check(rule) == []


def test_no_grouping_config_no_errors():
    assert check({"customDetails": {"A": "b"}}) == []


def test_field_path_points_at_offending_entry():
    rule = {
        "customDetails": {},
        "incidentConfiguration": {"groupingConfiguration": {
            "groupByCustomDetails": ["X"]}},
    }
    res = check(rule)
    assert res[0]["field"].endswith("groupByCustomDetails[0]")
