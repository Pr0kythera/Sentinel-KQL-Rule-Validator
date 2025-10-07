"""
Timing Validator
Validates queryFrequency and queryPeriod fields.
"""

import re
from pathlib import Path
from typing import List, Dict, Optional

from .base_validator import BaseValidator


class TimingValidator(BaseValidator):
    """Validates query timing fields"""
    
    @property
    def validator_name(self) -> str:
        return "Timing Validator"
    
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """Validate timing fields"""
        errors = []
        
        query_frequency = rule_data.get('queryFrequency')
        query_period = rule_data.get('queryPeriod')
        
        # Validate format and parse values
        freq_minutes = None
        period_minutes = None
        
        if query_frequency:
            freq_minutes, freq_error = self._parse_time_value(query_frequency, 'queryFrequency')
            if freq_error:
                errors.append(freq_error)
        
        if query_period:
            period_minutes, period_error = self._parse_time_value(query_period, 'queryPeriod')
            if period_error:
                errors.append(period_error)
        
        # Validate constraints if both values are valid
        if freq_minutes is not None and period_minutes is not None:
            # Check: queryFrequency <= queryPeriod
            if freq_minutes > period_minutes:
                errors.append(self.create_error(
                    f"queryFrequency '{query_frequency}' ({freq_minutes} minutes) cannot exceed "
                    f"queryPeriod '{query_period}' ({period_minutes} minutes)",
                    field='queryFrequency'
                ))
        
        if period_minutes is not None:
            # Check: queryPeriod <= 14 days (20160 minutes)
            max_period_minutes = 14 * 24 * 60  # 20160 minutes
            if period_minutes > max_period_minutes:
                errors.append(self.create_error(
                    f"queryPeriod '{query_period}' ({period_minutes} minutes) exceeds "
                    f"maximum of 14 days ({max_period_minutes} minutes)",
                    field='queryPeriod'
                ))
        
        return errors
    
    def _parse_time_value(self, time_str: str, field_name: str) -> tuple:
        """
        Parse time string to minutes.
        
        Args:
            time_str: Time string like '5m', '1h', '2d'
            field_name: Name of the field for error reporting
        
        Returns:
            Tuple of (minutes, error_dict)
            Returns (None, error) if parsing fails
            Returns (minutes, None) if parsing succeeds
        """
        if not isinstance(time_str, str):
            return None, self.create_error(
                f"Field '{field_name}' must be a string, got {type(time_str).__name__}",
                field=field_name
            )
        
        # Match pattern: number followed by unit (m, h, d)
        match = re.match(r'^(\d+)([mhd])$', time_str.lower())
        
        if not match:
            return None, self.create_error(
                f"Field '{field_name}' has invalid format: '{time_str}'. "
                f"Expected format: <number><unit> where unit is 'm' (minutes), 'h' (hours), or 'd' (days). "
                f"Examples: '5m', '1h', '2d'",
                field=field_name
            )
        
        value, unit = match.groups()
        value = int(value)
        
        # Convert to minutes
        unit_multipliers = {
            'm': 1,
            'h': 60,
            'd': 1440
        }
        
        minutes = value * unit_multipliers[unit]
        
        return minutes, None
