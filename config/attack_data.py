"""
MITRE ATT&CK data loader.

Reads the pinned Enterprise ATT&CK STIX bundle (see
config/attack/pinned_version.json) once and exposes fast lookups used by the
MITRE validator: valid tactic shortnames/names, valid technique IDs (main and
sub), each technique's tactic membership, and the valid DET / AN / DC ID sets.

Design notes:
- Parsing uses the standard-library json module plus dictionary filtering; the
  full stix2 library is not required for these lookups.
- Revoked (revoked == true) and deprecated (x_mitre_deprecated == true) objects
  are skipped. Both properties may be absent; absent is treated as false.
- The bundle is large (~48 MB). It is loaded at most once per (resolved) path
  and cached, so validating a directory of rules stays fast.
- The bundle is vendored, not fetched at runtime. If it is missing, loading
  raises AttackDataError with instructions to run the vendor step. Callers
  decide whether that is a hard error (offline mode) or a skip-with-warning.
"""

import json
from pathlib import Path

_ATTACK_DIR = Path(__file__).resolve().parent / "attack"
_PINNED_FILE = _ATTACK_DIR / "pinned_version.json"

_MITRE_SOURCE = "mitre-attack"
_KILL_CHAIN_NAME = "mitre-attack"

# Cache keyed by resolved absolute path string.
_CACHE = {}


class AttackDataError(Exception):
    """Raised when the pinned ATT&CK bundle cannot be loaded."""


def _load_pinned():
    with open(_PINNED_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)


def default_bundle_path():
    """Return the expected path of the vendored bundle from the pinned metadata."""
    pinned = _load_pinned()
    return _ATTACK_DIR / pinned["filename"]


def pinned_version():
    """Return the pinned ATT&CK version string (for example '18.1')."""
    return _load_pinned().get("attack_version", "unknown")


def _external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == _MITRE_SOURCE:
            return ref.get("external_id")
    return None


def _is_active(obj):
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


class AttackData:
    """Parsed, filtered view of one ATT&CK STIX bundle."""

    def __init__(self, version, tactic_names_by_shortname, technique_ids,
                 inactive_technique_ids, technique_tactics, det_ids, an_ids, dc_ids):
        self.version = version
        # shortname (for example 'command-and-control') -> display name
        self.tactic_names_by_shortname = tactic_names_by_shortname
        self.tactic_shortnames = set(tactic_names_by_shortname.keys())
        # all valid technique IDs, main (T####) and sub (T####.###)
        self.technique_ids = technique_ids
        # technique IDs that exist in the bundle but are deprecated or revoked,
        # so callers can distinguish "never existed" from "no longer current"
        self.inactive_technique_ids = inactive_technique_ids
        # technique ID -> set of tactic shortnames it belongs to
        self.technique_tactics = technique_tactics
        self.det_ids = det_ids
        self.an_ids = an_ids
        self.dc_ids = dc_ids

    @classmethod
    def from_bundle(cls, bundle, version):
        tactic_names_by_shortname = {}
        technique_ids = set()
        inactive_technique_ids = set()
        technique_tactics = {}
        det_ids = set()
        an_ids = set()
        dc_ids = set()

        for obj in bundle.get("objects", []):
            obj_type = obj.get("type")

            if obj_type == "x-mitre-tactic":
                # Tactics are not marked revoked/deprecated in practice, but
                # honor the flags if present for consistency.
                if not _is_active(obj):
                    continue
                shortname = obj.get("x_mitre_shortname")
                if shortname:
                    tactic_names_by_shortname[shortname] = obj.get("name", shortname)

            elif obj_type == "attack-pattern":
                tech_id = _external_id(obj)
                if not tech_id:
                    continue
                if not _is_active(obj):
                    inactive_technique_ids.add(tech_id)
                    continue
                technique_ids.add(tech_id)
                tactics = set()
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == _KILL_CHAIN_NAME:
                        phase_name = phase.get("phase_name")
                        if phase_name:
                            tactics.add(phase_name)
                technique_tactics[tech_id] = tactics

            elif obj_type == "x-mitre-detection-strategy":
                if not _is_active(obj):
                    continue
                det_id = _external_id(obj)
                if det_id:
                    det_ids.add(det_id)

            elif obj_type == "x-mitre-analytic":
                if not _is_active(obj):
                    continue
                an_id = _external_id(obj)
                if an_id:
                    an_ids.add(an_id)

            elif obj_type == "x-mitre-data-component":
                if not _is_active(obj):
                    continue
                dc_id = _external_id(obj)
                if dc_id:
                    dc_ids.add(dc_id)

        return cls(version, tactic_names_by_shortname, technique_ids,
                   inactive_technique_ids, technique_tactics, det_ids, an_ids, dc_ids)


def load_attack_data(bundle_path=None):
    """
    Load and cache the ATT&CK data.

    Args:
        bundle_path: optional override path to a STIX bundle JSON file. When
            omitted, the pinned bundle under config/attack/ is used.

    Returns:
        An AttackData instance.

    Raises:
        AttackDataError: if the bundle file is missing or cannot be parsed.
    """
    if bundle_path is None:
        path = default_bundle_path()
    else:
        path = Path(bundle_path)

    resolved = str(path.resolve()) if path.exists() else str(path)
    if resolved in _CACHE:
        return _CACHE[resolved]

    if not path.exists():
        raise AttackDataError(
            "ATT&CK STIX bundle not found at {}. Run the vendor step first: "
            "python scripts/vendor_attack_data.py".format(path)
        )

    try:
        with open(path, "r", encoding="utf-8") as handle:
            bundle = json.load(handle)
    except (OSError, ValueError) as exc:
        raise AttackDataError(
            "Failed to read ATT&CK STIX bundle {}: {}".format(path, exc)
        )

    version = pinned_version()
    data = AttackData.from_bundle(bundle, version)
    _CACHE[resolved] = data
    return data


# Explicit, tested mapping between the Sentinel tactic enum (PascalCase, no
# spaces) and ATT&CK tactic shortnames. Kept explicit rather than derived by
# string transformation so any drift between the two vocabularies is visible.
SENTINEL_TACTIC_TO_SHORTNAME = {
    "Reconnaissance": "reconnaissance",
    "ResourceDevelopment": "resource-development",
    "InitialAccess": "initial-access",
    "Execution": "execution",
    "Persistence": "persistence",
    "PrivilegeEscalation": "privilege-escalation",
    "DefenseEvasion": "defense-evasion",
    "CredentialAccess": "credential-access",
    "Discovery": "discovery",
    "LateralMovement": "lateral-movement",
    "Collection": "collection",
    "CommandAndControl": "command-and-control",
    "Exfiltration": "exfiltration",
    "Impact": "impact",
}

# Reverse map: ATT&CK shortname -> Sentinel enum name.
SHORTNAME_TO_SENTINEL_TACTIC = {
    short: name for name, short in SENTINEL_TACTIC_TO_SHORTNAME.items()
}
