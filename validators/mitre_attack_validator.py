"""
MITRE ATT&CK Validator

Validates a rule's tactics, relevantTechniques, and (optional) DET / AN / DC
identifiers against the pinned ATT&CK v18.x STIX bundle. This replaces the crude
hardcoded tactic list and T1000-T1999 regex range that previously lived in the
Sentinel constraints validator.

Behavior (see CLAUDE.md Task 2):
- tactics: validated against the explicit Sentinel tactic enum, then cross-checked
  against the ATT&CK tactic set. The "contains spaces" helpful error is preserved.
- relevantTechniques: format pre-check, then existence in the v18.x technique set.
  Distinguishes "invalid format", "valid format but not in ATT&CK v18.x", and
  "exists but is deprecated/revoked in v18.x".
- tactic/technique consistency: errors when a declared technique's ATT&CK tactic(s)
  are not among the rule's declared tactics, so the deployment pipeline fails until
  the correct tactic is added (Sentinel does not itself enforce this, but this gate
  does by choice).
- sub-technique parent consistency: confirms the parent technique exists.
- DET / AN / DC: format then existence. Warning severity by default (Sentinel does
  not consume these yet), promotable to error via enforce_detection_ids.

If the ATT&CK bundle is not vendored, existence checks are skipped with a clear
warning and only pure format checks run, so the gate never silently passes.
"""

import re
from pathlib import Path
from typing import List, Dict

from .base_validator import BaseValidator
from config.attack_data import (
    load_attack_data,
    AttackDataError,
    pinned_version,
    SENTINEL_TACTIC_TO_SHORTNAME,
    SHORTNAME_TO_SENTINEL_TACTIC,
)

# Format pre-checks. Existence against the STIX data is the real gate.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DET_RE = re.compile(r"^DET\d+$")
_AN_RE = re.compile(r"^AN\d+$")
_DC_RE = re.compile(r"^DC\d+$")


class MitreAttackValidator(BaseValidator):
    """Validates ATT&CK tactics, techniques, and detection-model identifiers."""

    def __init__(self, attack_stix_path=None, enforce_detection_ids: bool = False):
        """
        Args:
            attack_stix_path: optional override path to a STIX bundle JSON file.
            enforce_detection_ids: when True, DET/AN/DC existence failures are
                errors instead of warnings.
        """
        self.attack_stix_path = attack_stix_path
        self.enforce_detection_ids = enforce_detection_ids
        self._attack_data = None
        self._load_error = None
        self._load_attempted = False

    @property
    def validator_name(self) -> str:
        return "MITRE ATT&CK Validator"

    def _ensure_data(self):
        """Load ATT&CK data once, remembering any failure."""
        if self._load_attempted:
            return
        self._load_attempted = True
        try:
            self._attack_data = load_attack_data(self.attack_stix_path)
        except AttackDataError as exc:
            self._load_error = str(exc)

    def validate(self, rule_data: dict, file_path: Path,
                 all_files: List[Path] = None) -> List[Dict]:
        errors = []
        self._ensure_data()
        data = self._attack_data

        if data is None:
            # Existence checks unavailable; run format-only checks and say so.
            errors.append(self.create_warning(
                "MITRE ATT&CK existence checks skipped: {}".format(self._load_error),
                field='relevantTechniques'
            ))

        errors.extend(self._validate_tactics(rule_data, data))
        errors.extend(self._validate_techniques(rule_data, data))
        errors.extend(self._validate_tactic_technique_consistency(rule_data, data))
        errors.extend(self._validate_detection_model_ids(rule_data, data))
        return errors

    # -- tactics ---------------------------------------------------------------

    def _validate_tactics(self, rule_data, data) -> List[Dict]:
        errors = []
        tactics = rule_data.get('tactics')
        if not tactics:
            return errors  # required-field presence handled by schema validator
        if not isinstance(tactics, list):
            errors.append(self.create_error(
                "Field 'tactics' must be a list, got {}".format(type(tactics).__name__),
                field='tactics'
            ))
            return errors

        for idx, tactic in enumerate(tactics):
            if not isinstance(tactic, str):
                errors.append(self.create_error(
                    "Tactic at index {} must be a string, got {}".format(
                        idx, type(tactic).__name__),
                    field='tactics[{}]'.format(idx)
                ))
                continue

            if tactic in SENTINEL_TACTIC_TO_SHORTNAME:
                # Valid Sentinel enum value. Cross-check the shortname is present
                # in the loaded ATT&CK data when available.
                if data is not None:
                    shortname = SENTINEL_TACTIC_TO_SHORTNAME[tactic]
                    if shortname not in data.tactic_shortnames:
                        errors.append(self.create_warning(
                            "Tactic '{}' maps to ATT&CK shortname '{}' which is not "
                            "present in ATT&CK v{}.".format(
                                tactic, shortname, data.version),
                            field='tactics[{}]'.format(idx)
                        ))
                continue

            # Preserve the helpful "contains spaces" message.
            no_space = tactic.replace(" ", "")
            if no_space in SENTINEL_TACTIC_TO_SHORTNAME:
                errors.append(self.create_error(
                    "Tactic '{}' contains spaces. Sentinel tactics must not contain "
                    "spaces. Use '{}' instead.".format(tactic, no_space),
                    field='tactics[{}]'.format(idx)
                ))
            else:
                valid = ", ".join(sorted(SENTINEL_TACTIC_TO_SHORTNAME.keys()))
                errors.append(self.create_error(
                    "Tactic '{}' is not a valid Sentinel ATT&CK tactic. "
                    "Valid tactics are: {}".format(tactic, valid),
                    field='tactics[{}]'.format(idx)
                ))
        return errors

    # -- techniques ------------------------------------------------------------

    def _validate_techniques(self, rule_data, data) -> List[Dict]:
        errors = []
        techniques = rule_data.get('relevantTechniques')
        if not techniques:
            return errors
        if not isinstance(techniques, list):
            errors.append(self.create_error(
                "Field 'relevantTechniques' must be a list, got {}".format(
                    type(techniques).__name__),
                field='relevantTechniques'
            ))
            return errors

        for idx, technique in enumerate(techniques):
            field = 'relevantTechniques[{}]'.format(idx)
            if not isinstance(technique, str):
                errors.append(self.create_error(
                    "Technique at index {} must be a string, got {}".format(
                        idx, type(technique).__name__),
                    field=field
                ))
                continue

            if not _TECHNIQUE_RE.match(technique):
                errors.append(self.create_error(
                    "Technique '{}' has invalid format. Must be 'T####' (for example "
                    "T1059) or 'T####.###' (for example T1059.001).".format(technique),
                    field=field
                ))
                continue

            if data is None:
                continue  # existence unavailable; format check already passed

            if technique in data.technique_ids:
                # Sub-technique parent consistency.
                if "." in technique:
                    parent = technique.split(".")[0]
                    if parent not in data.technique_ids:
                        errors.append(self.create_warning(
                            "Sub-technique '{}' is valid but its parent '{}' does not "
                            "exist as an active technique in ATT&CK v{}.".format(
                                technique, parent, data.version),
                            field=field
                        ))
                continue

            if technique in data.inactive_technique_ids:
                errors.append(self.create_error(
                    "Technique '{}' exists in ATT&CK but is deprecated or revoked in "
                    "v{}. Use a current technique.".format(technique, data.version),
                    field=field
                ))
            else:
                errors.append(self.create_error(
                    "Technique '{}' has a valid format but does not exist in "
                    "ATT&CK v{}.".format(technique, data.version),
                    field=field
                ))
        return errors

    # -- tactic/technique consistency -----------------------------------------

    def _validate_tactic_technique_consistency(self, rule_data, data) -> List[Dict]:
        errors = []
        if data is None:
            return errors
        tactics = rule_data.get('tactics')
        techniques = rule_data.get('relevantTechniques')
        if not isinstance(tactics, list) or not isinstance(techniques, list):
            return errors

        declared_shortnames = set()
        for tactic in tactics:
            if isinstance(tactic, str) and tactic in SENTINEL_TACTIC_TO_SHORTNAME:
                declared_shortnames.add(SENTINEL_TACTIC_TO_SHORTNAME[tactic])

        for idx, technique in enumerate(techniques):
            if not isinstance(technique, str) or technique not in data.technique_ids:
                continue
            # A sub-technique inherits tactic membership from its own entry; if
            # absent, fall back to the parent's membership.
            tech_tactics = data.technique_tactics.get(technique)
            if not tech_tactics and "." in technique:
                tech_tactics = data.technique_tactics.get(technique.split(".")[0])
            if not tech_tactics:
                continue
            if not (tech_tactics & declared_shortnames):
                expected = ", ".join(sorted(
                    SHORTNAME_TO_SENTINEL_TACTIC.get(s, s) for s in tech_tactics))
                errors.append(self.create_error(
                    "Technique '{}' belongs to tactic(s) {} but none of those are in "
                    "the rule's declared tactics. Add the correct tactic.".format(
                        technique, expected),
                    field='relevantTechniques[{}]'.format(idx)
                ))
        return errors

    # -- DET / AN / DC ---------------------------------------------------------

    def _validate_detection_model_ids(self, rule_data, data) -> List[Dict]:
        errors = []
        specs = [
            ('detectionStrategies', _DET_RE, 'DET',
             (data.det_ids if data is not None else None)),
            ('analytics', _AN_RE, 'AN',
             (data.an_ids if data is not None else None)),
            ('dataComponents', _DC_RE, 'DC',
             (data.dc_ids if data is not None else None)),
        ]
        for field_name, pattern, label, valid_ids in specs:
            values = rule_data.get(field_name)
            if not values:
                continue
            if not isinstance(values, list):
                errors.append(self.create_error(
                    "Field '{}' must be a list, got {}".format(
                        field_name, type(values).__name__),
                    field=field_name
                ))
                continue
            for idx, value in enumerate(values):
                field = '{}[{}]'.format(field_name, idx)
                if not isinstance(value, str) or not value.strip():
                    errors.append(self.create_error(
                        "{} entry at index {} must be a non-empty string.".format(
                            label, idx),
                        field=field
                    ))
                    continue
                if not pattern.match(value):
                    errors.append(self.create_error(
                        "{} identifier '{}' has invalid format. Must be '{}' followed "
                        "by digits (for example {}0001).".format(
                            label, value, label, label),
                        field=field
                    ))
                    continue
                if valid_ids is None:
                    continue  # existence unavailable
                if value not in valid_ids:
                    msg = ("{} identifier '{}' does not exist in ATT&CK v{}."
                           .format(label, value, data.version))
                    if self.enforce_detection_ids:
                        errors.append(self.create_error(msg, field=field))
                    else:
                        errors.append(self.create_warning(msg, field=field))
        return errors
