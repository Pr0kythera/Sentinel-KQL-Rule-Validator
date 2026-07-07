"""Tests for MitreAttackValidator."""

from pathlib import Path

import pytest

from validators.mitre_attack_validator import MitreAttackValidator

FILE = Path("rule.yaml")


def severities(results):
    return [r['severity'] for r in results]


def messages(results):
    return " || ".join(r['message'] for r in results)


@pytest.fixture
def validator(attack_data):
    # Depend on attack_data so the suite skips when the bundle is missing.
    return MitreAttackValidator()


def test_valid_tactic_and_technique_pass(validator):
    rule = {"tactics": ["Execution"], "relevantTechniques": ["T1059"]}
    assert validator.validate(rule, FILE) == []


def test_tactic_with_spaces_errors_with_fix(validator):
    rule = {"tactics": ["Command And Control"], "relevantTechniques": ["T1071"]}
    results = validator.validate(rule, FILE)
    assert any(r['severity'] == 'error' and 'CommandAndControl' in r['message']
               for r in results)


def test_unknown_tactic_errors(validator):
    rule = {"tactics": ["NotARealTactic"], "relevantTechniques": ["T1059"]}
    results = validator.validate(rule, FILE)
    assert any(r['severity'] == 'error' and 'not a valid Sentinel' in r['message']
               for r in results)


def test_bad_technique_format_errors(validator):
    rule = {"tactics": ["Impact"], "relevantTechniques": ["T10"]}
    results = validator.validate(rule, FILE)
    assert any('invalid format' in r['message'] for r in results)


def test_nonexistent_technique_errors(validator):
    rule = {"tactics": ["Impact"], "relevantTechniques": ["T9999"]}
    results = validator.validate(rule, FILE)
    assert any('does not exist' in r['message'] for r in results)


def test_revoked_technique_errors_distinctly(validator):
    rule = {"tactics": ["DefenseEvasion"], "relevantTechniques": ["T1066"]}
    results = validator.validate(rule, FILE)
    assert any('deprecated or revoked' in r['message'] for r in results)


def test_tactic_technique_consistency_errors(validator):
    # T1071 is Command and Control; declaring only Execution must be an error so
    # the deployment pipeline fails.
    rule = {"tactics": ["Execution"], "relevantTechniques": ["T1071"]}
    results = validator.validate(rule, FILE)
    assert any(r['severity'] == 'error' and 'declared tactics' in r['message']
               for r in results)


def test_det_format_error_and_existence_warning(validator):
    rule = {"tactics": ["Execution"], "relevantTechniques": ["T1059"],
            "detectionStrategies": ["BADFMT", "DET9999"]}
    results = validator.validate(rule, FILE)
    assert any(r['severity'] == 'error' and 'invalid format' in r['message']
               for r in results)
    assert any(r['severity'] == 'warning' and 'does not exist' in r['message']
               for r in results)


def test_det_existence_promoted_to_error_when_enforced(attack_data):
    v = MitreAttackValidator(enforce_detection_ids=True)
    rule = {"tactics": ["Execution"], "relevantTechniques": ["T1059"],
            "detectionStrategies": ["DET9999"]}
    results = v.validate(rule, FILE)
    assert any(r['severity'] == 'error' and 'does not exist' in r['message']
               for r in results)


def test_missing_bundle_skips_with_warning_but_keeps_format_checks(tmp_path):
    # Point at a nonexistent bundle: existence checks skip (warning), format still runs.
    missing = tmp_path / "nope.json"
    v = MitreAttackValidator(attack_stix_path=str(missing))
    rule = {"tactics": ["Execution"], "relevantTechniques": ["T10"]}
    results = v.validate(rule, FILE)
    assert any('existence checks skipped' in r['message'] for r in results)
    assert any('invalid format' in r['message'] for r in results)
