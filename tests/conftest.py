"""
Shared pytest fixtures.

Tests are designed to run without a live network. Tests that need the vendored
ATT&CK STIX bundle skip cleanly (with a clear reason) when it is not present,
rather than failing, so the suite is usable on a machine that has not run the
vendor step. KQL tests likewise skip when the .NET runtime / DLL cannot load.
"""

import sys
from pathlib import Path

import pytest

# Ensure the project root is importable when pytest is run from anywhere.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def attack_data():
    """Load the vendored ATT&CK data, or skip if the bundle is not present."""
    from config.attack_data import load_attack_data, AttackDataError
    try:
        return load_attack_data()
    except AttackDataError as exc:
        pytest.skip("ATT&CK bundle not vendored: {}".format(exc))


@pytest.fixture(scope="session")
def kql_validator():
    """Construct a KQLValidator, or skip if .NET / the DLL is unavailable."""
    from validators.kql_validator import KQLValidator
    try:
        return KQLValidator()
    except Exception as exc:  # noqa: BLE001 - environment guard
        pytest.skip("KQL validator unavailable (.NET/DLL): {}".format(exc))
