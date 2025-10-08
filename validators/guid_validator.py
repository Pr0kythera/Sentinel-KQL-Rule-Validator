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
        """Find other files with the same GUID"""
        duplicates = []
        
        # Resolve current file path for accurate comparison
        # This handles symlinks and different path representations
        current_file_resolved = current_file.resolve()
        
        for file_path in all_files:
            # Skip the current file (compare resolved paths)
            if file_path.resolve() == current_file_resolved:
                continue
            
            try:
                other_rule = load_yaml_file(file_path)
                other_guid = other_rule.get('id')
                
                if other_guid and str(other_guid).lower() == str(guid).lower():
                    duplicates.append(file_path)
            except Exception:
                # Skip files that can't be loaded
                continue
        
        return duplicates
