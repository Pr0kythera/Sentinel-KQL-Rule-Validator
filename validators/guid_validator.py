"""
GUID Validator
Validates that the 'id' field contains a valid GUID and is unique across files.
"""

import uuid
from pathlib import Path
from typing import List, Dict

from .base_validator import BaseValidator
from utils.yaml_loader import load_yaml_file


class GuidValidator(BaseValidator):
    """Validates GUID format and uniqueness"""
    
    @property
    def validator_name(self) -> str:
        return "GUID Validator"
    
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """Validate GUID format and uniqueness"""
        errors = []
        
        # Check if 'id' field exists
        if 'id' not in rule_data:
            errors.append(self.create_error(
                "Missing required field 'id'",
                field='id'
            ))
            return errors
        
        guid_value = rule_data['id']
        
        # Validate GUID format
        if not self._is_valid_guid(guid_value):
            errors.append(self.create_error(
                f"Field 'id' contains invalid GUID format: '{guid_value}'. "
                f"Expected format: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'",
                field='id'
            ))
            return errors  # Don't check uniqueness if format is invalid
        
        # Check uniqueness across files
        if all_files:
            duplicate_files = self._find_duplicate_guids(guid_value, file_path, all_files)
            if duplicate_files:
                file_list = ', '.join(str(f.name) for f in duplicate_files)
                errors.append(self.create_error(
                    f"GUID '{guid_value}' is not unique. Also found in: {file_list}",
                    field='id'
                ))
        
        return errors
    
    def _is_valid_guid(self, value: str) -> bool:
        """Check if value is a valid GUID/UUID"""
        if not isinstance(value, str):
            return False
        
        try:
            uuid.UUID(value)
            return True
        except (ValueError, AttributeError, TypeError):
            return False
    
    def _find_duplicate_guids(self, guid: str, current_file: Path, all_files: List[Path]) -> List[Path]:
        """Find other files with the same GUID (robust comparison)."""
        duplicates = []

        try:
            current_file_resolved = Path(current_file).resolve()
        except Exception:
            current_file_resolved = None

        # Normalize the GUID to a comparable string
        guid_norm = str(guid).strip().lower()

        for file_entry in all_files:
            try:
                other_path = Path(file_entry)
            except Exception:
                # skip invalid path entries
                continue

            # Skip the current file (compare resolved paths when possible)
            try:
                if current_file_resolved and other_path.resolve() == current_file_resolved:
                    continue
            except Exception:
                # if resolve fails, fall back to string comparison
                if str(other_path) == str(current_file):
                    continue

            try:
                other_rule = load_yaml_file(other_path)
            except Exception:
                # Skip files that can't be loaded
                continue

            other_guid = other_rule.get('id')
            if other_guid is None:
                continue

            # Normalize and compare
            if str(other_guid).strip().lower() == guid_norm:
                duplicates.append(other_path)

        return duplicates
