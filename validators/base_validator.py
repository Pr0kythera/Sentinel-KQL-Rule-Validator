"""
Base validator abstract class for all validation checks.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict


class ValidationError:
    """Represents a validation error or warning"""
    
    def __init__(self, severity: str, message: str, field: str = None, **kwargs):
        self.severity = severity  # 'error' or 'warning'
        self.message = message
        self.field = field
        self.extra = kwargs
    
    def to_dict(self) -> Dict:
        """Convert to dictionary format"""
        result = {
            'severity': self.severity,
            'message': self.message
        }
        if self.field:
            result['field'] = self.field
        result.update(self.extra)
        return result


class BaseValidator(ABC):
    """Abstract base class for all validators"""
    
    @property
    @abstractmethod
    def validator_name(self) -> str:
        """Human-readable name of the validator"""
        pass
    
    @abstractmethod
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """
        Validate the rule data.
        
        Args:
            rule_data: Parsed YAML data as dictionary
            file_path: Path to the file being validated
            all_files: List of all YAML files (for cross-file validation)
        
        Returns:
            List of error/warning dictionaries
        """
        pass
    
    def create_error(self, message: str, field: str = None, **kwargs) -> Dict:
        """Helper to create an error dictionary"""
        return ValidationError('error', message, field, **kwargs).to_dict()
    
    def create_warning(self, message: str, field: str = None, **kwargs) -> Dict:
        """Helper to create a warning dictionary"""
        return ValidationError('warning', message, field, **kwargs).to_dict()
