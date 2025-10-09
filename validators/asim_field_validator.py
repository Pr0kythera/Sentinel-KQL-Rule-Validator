"""
ASIM Field Validator
Validates that entity mapping columnName values follow ASIM (Advanced Security Information Model)
normalized field naming conventions.
Reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-common-fields
"""

from pathlib import Path
from typing import List, Dict

from .base_validator import BaseValidator
from config.asim_field_names import VALID_ASIM_FIELD_NAMES, ENTITY_TO_ASIM_PATTERNS


class ASIMFieldValidator(BaseValidator):
    """Validates entity mapping column names against ASIM conventions"""
    
    @property
    def validator_name(self) -> str:
        return "ASIM Field Validator"
    
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """Validate entity mapping column names follow ASIM conventions"""
        errors = []
        
        entity_mappings = rule_data.get('entityMappings', [])
        
        if not entity_mappings:
            return errors  # No entity mappings to validate
        
        if not isinstance(entity_mappings, list):
            # This would be caught by schema validator, skip
            return errors
        
        # Validate each entity mapping
        for idx, entity in enumerate(entity_mappings):
            if not isinstance(entity, dict):
                continue
            
            entity_errors = self._validate_entity_asim_fields(entity, idx)
            errors.extend(entity_errors)
        
        return errors
    
    def _validate_entity_asim_fields(self, entity: dict, index: int) -> List[Dict]:
        """Validate ASIM field names for a single entity mapping"""
        errors = []
        
        entity_type = entity.get('entityType')
        if not entity_type:
            # Missing entity type would be caught by entity validator
            return errors
        
        field_mappings = entity.get('fieldMappings', [])
        if not field_mappings:
            # Missing field mappings would be caught by entity validator
            return errors
        
        # Validate each field mapping
        for field_idx, field_mapping in enumerate(field_mappings):
            if not isinstance(field_mapping, dict):
                continue
            
            column_name = field_mapping.get('columnName')
            identifier = field_mapping.get('identifier')
            
            if not column_name:
                # Missing columnName would be caught by entity validator
                continue
            
            # Check if column name follows ASIM conventions
            if not self._is_valid_asim_field(column_name):
                warning = self._create_asim_field_warning(
                    entity_type, column_name, identifier, index, field_idx
                )
                errors.append(warning)
        
        return errors
    
    def _is_valid_asim_field(self, field_name: str) -> bool:
        """
        Check if a field name is a valid ASIM normalized field name.
        
        Args:
            field_name: The field name to validate
        
        Returns:
            True if the field name is in the ASIM field list, False otherwise
        """
        if not isinstance(field_name, str):
            return False
        
        # Check exact match
        if field_name in VALID_ASIM_FIELD_NAMES:
            return True
        
        # Case-insensitive check (ASIM fields are case-sensitive but we can be lenient)
        field_name_normalized = field_name
        for valid_field in VALID_ASIM_FIELD_NAMES:
            if valid_field.lower() == field_name.lower():
                return True
        
        return False
    
    def _create_asim_field_warning(self, entity_type: str, column_name: str, 
                                   identifier: str, entity_idx: int, field_idx: int) -> Dict:
        """
        Create a warning message for non-ASIM field names.
        
        Args:
            entity_type: The type of entity
            column_name: The non-ASIM column name
            identifier: The identifier being mapped
            entity_idx: Index of entity in entityMappings list
            field_idx: Index of field mapping in fieldMappings list
        
        Returns:
            Warning dictionary
        """
        # Build helpful message with entity-specific recommendations
        message_parts = [
            f"Entity mapping for '{entity_type}' uses columnName '{column_name}' "
            f"which does not follow ASIM normalized field naming conventions."
        ]
        
        # Provide entity-specific guidance if available
        if entity_type in ENTITY_TO_ASIM_PATTERNS:
            pattern_info = ENTITY_TO_ASIM_PATTERNS[entity_type]
            examples = pattern_info.get('examples', [])
            
            if examples:
                message_parts.append(
                    f"For '{entity_type}' entities, ASIM recommends field names like: "
                    f"{', '.join(examples[:4])}."
                )
            
            prefixes = pattern_info.get('prefixes', [])
            if prefixes:
                message_parts.append(
                    f"Typical prefixes for this entity type: {', '.join(prefixes)}."
                )
        else:
            # Generic guidance for unknown entity types
            message_parts.append(
                "Please refer to ASIM documentation for recommended field names: "
                "https://learn.microsoft.com/en-us/azure/sentinel/normalization-common-fields"
            )
        
        message_parts.append(
            "Using ASIM-normalized field names improves query consistency and "
            "cross-source correlation."
        )
        
        message = " ".join(message_parts)
        
        return self.create_warning(
            message,
            field=f'entityMappings[{entity_idx}].fieldMappings[{field_idx}].columnName'
        )
    
    def get_asim_suggestions(self, entity_type: str, current_field: str) -> List[str]:
        """
        Get ASIM field suggestions for a given entity type and current field name.
        This can be used for enhanced error messages or tooling.
        
        Args:
            entity_type: The entity type
            current_field: The current (non-ASIM) field name
        
        Returns:
            List of suggested ASIM field names
        """
        suggestions = []
        
        if entity_type not in ENTITY_TO_ASIM_PATTERNS:
            return suggestions
        
        pattern_info = ENTITY_TO_ASIM_PATTERNS[entity_type]
        prefixes = pattern_info.get('prefixes', [])
        base_fields = pattern_info.get('base_fields', [])
        
        # Try to match based on the current field name
        current_lower = current_field.lower()
        
        # Look for potential base field matches
        for base_field in base_fields:
            if base_field.lower() in current_lower or current_lower in base_field.lower():
                # Add prefixed versions
                if prefixes:
                    for prefix in prefixes:
                        suggestions.append(f"{prefix}{base_field}")
                else:
                    suggestions.append(base_field)
        
        # If no matches, return examples
        if not suggestions:
            suggestions = pattern_info.get('examples', [])[:3]
        
        return suggestions
