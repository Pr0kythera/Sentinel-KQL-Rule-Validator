"""
Schema Validator
Validates YAML structure and data types against expected schema.
"""

from pathlib import Path
from typing import List, Dict, Any

from .base_validator import BaseValidator
from config.schema_definition import EXPECTED_TYPES, REQUIRED_FIELDS


class SchemaValidator(BaseValidator):
    """Validates YAML structure and data types"""
    
    @property
    def validator_name(self) -> str:
        return "Schema Validator"
    
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """Validate schema structure and data types"""
        errors = []
        
        # Check required fields
        for field in REQUIRED_FIELDS:
            if field not in rule_data:
                errors.append(self.create_error(
                    f"Missing required field '{field}'",
                    field=field
                ))
        
        # Validate data types
        for field_path, expected_type in EXPECTED_TYPES.items():
            error = self._validate_field_type(rule_data, field_path, expected_type)
            if error:
                errors.append(error)
        
        return errors
    
    def _validate_field_type(self, data: dict, field_path: str, expected_type: type) -> Dict:
        """
        Validate a single field's type.
        
        Args:
            data: The rule data dictionary
            field_path: Dot-separated path to the field (e.g., 'incidentConfiguration.createIncident')
            expected_type: Expected Python type
        
        Returns:
            Error dict if validation fails, None otherwise
        """
        # Navigate to the field using dot notation
        current = data
        path_parts = field_path.split('.')
        
        try:
            for part in path_parts:
                if not isinstance(current, dict):
                    return None  # Parent doesn't exist, skip
                current = current.get(part)
                if current is None:
                    return None  # Field doesn't exist, not an error (might be optional)
            
            # Check type
            if not isinstance(current, expected_type):
                actual_type = type(current).__name__
                expected_type_name = expected_type.__name__
                
                # Special handling for bool vs string
                if expected_type == bool and isinstance(current, str):
                    return self.create_error(
                        f"Field '{field_path}' has incorrect type. "
                        f"Expected {expected_type_name}, got {actual_type}. "
                        f"Use {field_path}: true instead of {field_path}: 'true'",
                        field=field_path
                    )
                else:
                    return self.create_error(
                        f"Field '{field_path}' has incorrect type. "
                        f"Expected {expected_type_name}, got {actual_type}",
                        field=field_path
                    )
        
        except Exception as e:
            return self.create_error(
                f"Error validating field '{field_path}': {str(e)}",
                field=field_path
            )
        
        return None
