"""Tests for the ATT&CK data loader (config/attack_data.py)."""

from config.attack_data import (
    SENTINEL_TACTIC_TO_SHORTNAME,
    SHORTNAME_TO_SENTINEL_TACTIC,
    pinned_version,
)


def test_pinned_version_is_v18():
    assert pinned_version().startswith("18")


def test_sentinel_tactic_map_has_14_entries():
    # The Sentinel tactic enum has 14 members matching ATT&CK v18 tactics.
    assert len(SENTINEL_TACTIC_TO_SHORTNAME) == 14


def test_sentinel_tactic_map_round_trips():
    for name, short in SENTINEL_TACTIC_TO_SHORTNAME.items():
        assert SHORTNAME_TO_SENTINEL_TACTIC[short] == name


def test_tactic_shortnames_match_bundle(attack_data):
    # Every Sentinel-mapped shortname must exist in the loaded ATT&CK tactic set.
    for short in SENTINEL_TACTIC_TO_SHORTNAME.values():
        assert short in attack_data.tactic_shortnames


def test_known_active_and_revoked_techniques(attack_data):
    # T1059 (Command and Scripting Interpreter) is a stable active technique.
    assert "T1059" in attack_data.technique_ids
    # T1066 was revoked; it must not be in the active set.
    assert "T1066" not in attack_data.technique_ids
    assert "T1066" in attack_data.inactive_technique_ids


def test_detection_model_id_sets_non_empty(attack_data):
    assert attack_data.det_ids, "expected DET ids in v18 bundle"
    assert attack_data.an_ids, "expected AN ids in v18 bundle"
    assert attack_data.dc_ids, "expected DC ids in v18 bundle"


def test_technique_tactic_membership(attack_data):
    # T1059 belongs to the Execution tactic.
    assert "execution" in attack_data.technique_tactics.get("T1059", set())
