"""
Entity Validator
Validates entity mappings use strong identifiers and reference valid columns.
"""

from pathlib import Path
from typing import List, Dict

from .base_validator import BaseValidator
from config.entity_identifiers import ENTITY_STRONG_IDENTIFIERS


class EntityValidator(BaseValidator):
    """Validates entity mappings"""
    
    @property
    def validator_name(self) -> str:
        return "Entity Validator"
    
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """Validate entity mappings"""
        errors = []
        
        entity_mappings = rule_data.get('entityMappings', [])
        
        if not entity_mappings:
            return errors  # No entity mappings to validate
        
        if not isinstance(entity_mappings, list):
            errors.append(self.create_error(
                "Field 'entityMappings' must be a list",
                field='entityMappings'
            ))
            return errors
        
        # Validate each entity mapping
        for idx, entity in enumerate(entity_mappings):
            entity_errors = self._validate_entity(entity, idx)
            errors.extend(entity_errors)
        
        return errors
    
    def _validate_entity(self, entity: dict, index: int) -> List[Dict]:
        """Validate a single entity mapping"""
        errors = []
        
        if not isinstance(entity, dict):
            errors.append(self.create_error(
                f"Entity mapping at index {index} must be a dictionary",
                field=f'entityMappings[{index}]'
            ))
            return errors
        
        # Check required fields
        entity_type = entity.get('entityType')
        if not entity_type:
            errors.append(self.create_error(
                f"Entity mapping at index {index} missing 'entityType'",
                field=f'entityMappings[{index}].entityType'
            ))
            return errors
        
        field_mappings = entity.get('fieldMappings', [])
        if not field_mappings:
            errors.append(self.create_error(
                f"Entity '{entity_type}' has no fieldMappings",
                field=f'entityMappings[{index}].fieldMappings'
            ))
            return errors
        
        # Validate field mappings
        for field_idx, field_mapping in enumerate(field_mappings):
            if not isinstance(field_mapping, dict):
                continue
            
            identifier = field_mapping.get('identifier')
            column_name = field_mapping.get('columnName')
            
            if not identifier:
                errors.append(self.create_error(
                    f"Field mapping for entity '{entity_type}' missing 'identifier'",
                    field=f'entityMappings[{index}].fieldMappings[{field_idx}].identifier'
                ))
                continue
            
            if not column_name:
                errors.append(self.create_error(
                    f"Field mapping for entity '{entity_type}' missing 'columnName'",
                    field=f'entityMappings[{index}].fieldMappings[{field_idx}].columnName'
                ))
                continue
            
            # Validate strong identifier
            identifier_error = self._validate_strong_identifier(
                entity_type, identifier, index, field_idx
            )
            if identifier_error:
                errors.append(identifier_error)
        
        return errors
    
    def _validate_strong_identifier(self, entity_type: str, identifier: str, 
                                entity_idx: int, field_idx: int) -> Dict:
        """
        Validate that the identifier is a strong identifier for the entity type.

        Reference: https://learn.microsoft.com/en-us/azure/sentinel/entities-reference
        """
        # Check if entity type exists with exact case match
        if entity_type not in ENTITY_STRONG_IDENTIFIERS:
            # Check if it exists with different casing
            correct_case = self._find_correct_entity_case(entity_type)
            
            if correct_case:
                # Entity exists but with wrong casing - this is an ERROR
                return self.create_error(
                    f"Invalid entity type casing '{entity_type}'. "
                    f"Entity types are case-sensitive. Use '{correct_case}' instead.",
                    field=f'entityMappings[{entity_idx}].entityType'
                )
            else:
                # Entity doesn't exist at all - list valid options
                valid_types = ', '.join(sorted(ENTITY_STRONG_IDENTIFIERS.keys()))
                return self.create_error(
                    f"Unknown entity type '{entity_type}'. "
                    f"Valid entity types are: {valid_types}",
                    field=f'entityMappings[{entity_idx}].entityType'
                )
        
        strong_identifiers = ENTITY_STRONG_IDENTIFIERS[entity_type]
        
        # Find correct case for identifier
        correct_identifier = None
        for valid_id in strong_identifiers:
            if valid_id.lower() == identifier.lower():
                correct_identifier = valid_id
                if valid_id != identifier:
                    return self.create_error(
                        f"Invalid identifier casing '{identifier}'. "
                        f"Identifiers are case-sensitive. Use '{valid_id}' instead.",
                        field=f'entityMappings[{entity_idx}].fieldMappings[{field_idx}].identifier'
                    )
                break

        if not correct_identifier:
            valid_ids = ', '.join(strong_identifiers)
            return self.create_warning(
                f"Entity type '{entity_type}' is using identifier '{identifier}' which may not be "
                f"a strong identifier. Recommended strong identifiers: {valid_ids}",
                field=f'entityMappings[{entity_idx}].fieldMappings[{field_idx}].identifier'
            )
        
        return None
    
def _find_correct_entity_case(self, entity_type: str) -> str:
    """
    Find the correct casing for an entity type if it exists.
    
    Args:
        entity_type: Entity type with potentially incorrect casing
    
    Returns:
        Correctly cased entity type if found, None otherwise
    """
    if not entity_type:
        return None
        
    entity_lower = entity_type.lower()
    
    for valid_entity in ENTITY_STRONG_IDENTIFIERS:
        if valid_entity.lower() == entity_lower:
            return valid_entity
    
    return None
