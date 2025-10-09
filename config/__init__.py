"""
Configuration package for Sentinel Detection Linter
"""

from .schema_definition import EXPECTED_TYPES, REQUIRED_FIELDS, SENTINEL_SCHEMA
from .entity_identifiers import ENTITY_STRONG_IDENTIFIERS
from .asim_field_names import VALID_ASIM_FIELD_NAMES, ENTITY_TO_ASIM_PATTERNS

__all__ = [
    'EXPECTED_TYPES',
    'REQUIRED_FIELDS',
    'SENTINEL_SCHEMA',
    'ENTITY_STRONG_IDENTIFIERS',
    'VALID_ASIM_FIELD_NAMES',
    'ENTITY_TO_ASIM_PATTERNS'
]
