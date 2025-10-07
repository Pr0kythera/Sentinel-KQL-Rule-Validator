"""
Configuration package for Sentinel Detection Linter
"""

from .schema_definition import EXPECTED_TYPES, REQUIRED_FIELDS, SENTINEL_SCHEMA
from .entity_identifiers import ENTITY_STRONG_IDENTIFIERS

__all__ = [
    'EXPECTED_TYPES',
    'REQUIRED_FIELDS',
    'SENTINEL_SCHEMA',
    'ENTITY_STRONG_IDENTIFIERS'
]
