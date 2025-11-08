"""
Sentinel Constraints Validator
Validates Microsoft Sentinel Analytics Rule field constraints and requirements.
Reference: https://learn.microsoft.com/en-us/azure/sentinel/sentinel-analytic-rules-creation
"""

import re
from pathlib import Path
from typing import List, Dict

from .base_validator import BaseValidator


class SentinelConstraintsValidator(BaseValidator):
    """Validates Sentinel-specific field constraints and requirements"""
    
    # Valid values for kind field
    VALID_KINDS = ["Scheduled", "NRT"]
    
    # Valid values for severity field
    VALID_SEVERITIES = ["Informational", "Low", "Medium", "High"]
    
    # Valid values for triggerOperator field
    VALID_TRIGGER_OPERATORS = ["GreaterThan", "LessThan", "Equal", "gt", "lt", "eq"]
    
    # Valid MITRE ATT&CK v13 tactics (no spaces)
    VALID_TACTICS = [
        "Reconnaissance",
        "ResourceDevelopment",
        "InitialAccess",
        "Execution",
        "Persistence",
        "PrivilegeEscalation",
        "DefenseEvasion",
        "CredentialAccess",
        "Discovery",
        "LateralMovement",
        "Collection",
        "CommandAndControl",
        "Exfiltration",
        "Impact"
    ]
    
    # Valid values for eventGroupingSettings.aggregationKind
    VALID_AGGREGATION_KINDS = ["SingleAlert", "AlertPerResult"]
    
    # Constraint limits
    MAX_NAME_LENGTH = 50
    MAX_DESCRIPTION_LENGTH = 255
    MAX_QUERY_LENGTH = 10000
    MAX_TRIGGER_THRESHOLD = 10000
    MAX_ENTITY_MAPPINGS = 10
    MAX_FIELD_MAPPINGS_PER_ENTITY = 3
    MAX_CUSTOM_DETAILS = 20
    MAX_ALERT_NAME_LENGTH = 256
    MAX_ALERT_DESCRIPTION_LENGTH = 5000
    MAX_ALERT_PARAMETERS = 3
    
    @property
    def validator_name(self) -> str:
        return "Sentinel Constraints Validator"
    
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """Validate Sentinel-specific constraints"""
        errors = []
        
        # Validate kind field
        errors.extend(self._validate_kind(rule_data))
        
        # Validate severity field
        errors.extend(self._validate_severity(rule_data))
        
        # Validate triggerOperator field
        errors.extend(self._validate_trigger_operator(rule_data))
        
        # Validate triggerThreshold field
        errors.extend(self._validate_trigger_threshold(rule_data))
        
        # Validate tactics field
        errors.extend(self._validate_tactics(rule_data))
        
        # Validate relevantTechniques field
        errors.extend(self._validate_relevant_techniques(rule_data))
        
        # Validate name field constraints
        errors.extend(self._validate_name_constraints(rule_data))
        
        # Validate description field constraints
        errors.extend(self._validate_description_constraints(rule_data))
        
        # Validate query field constraints
        errors.extend(self._validate_query_constraints(rule_data))
        
        # Validate version field format
        errors.extend(self._validate_version(rule_data))
        
        # Validate eventGroupingSettings
        errors.extend(self._validate_event_grouping(rule_data))
        
        # Validate entity mappings limits
        errors.extend(self._validate_entity_mappings_limits(rule_data))
        
        # Validate customDetails limits
        errors.extend(self._validate_custom_details(rule_data))
        
        # Validate alertDetailsOverride constraints
        errors.extend(self._validate_alert_details_override(rule_data))
        
        # Validate Grouping Errors
        errors.extend(self._validate_grouping_configuration(rule_data))
        
        return errors
    
    def _validate_kind(self, rule_data: dict) -> List[Dict]:
        """Validate kind field"""
        errors = []
        
        kind = rule_data.get('kind')
        if not kind or not kind.strip():
            errors.append(self.create_error(
                "Field 'kind' cannot be empty",
                field='kind'
            ))
            return errors
        
        if kind not in self.VALID_KINDS:
            valid_values = "', '".join(self.VALID_KINDS)
            errors.append(self.create_error(
                f"Field 'kind' has invalid value '{kind}'. "
                f"Must be one of: '{valid_values}'",
                field='kind'
            ))
        
        return errors
    
    def _validate_severity(self, rule_data: dict) -> List[Dict]:
        """Validate severity field"""
        errors = []
        
        severity = rule_data.get('severity')
        if not severity or not severity.strip():
            errors.append(self.create_error(
                "Field 'severity' cannot be empty",
                field='severity'
            ))
            return errors
        
        if severity not in self.VALID_SEVERITIES:
            valid_values = "', '".join(self.VALID_SEVERITIES)
            errors.append(self.create_error(
                f"Field 'severity' has invalid value '{severity}'. "
                f"Must be one of: '{valid_values}'",
                field='severity'
            ))
        
        return errors
    
    def _validate_trigger_operator(self, rule_data: dict) -> List[Dict]:
        """Validate triggerOperator field"""
        errors = []
        
        trigger_operator = rule_data.get('triggerOperator')
        if not trigger_operator or not trigger_operator.strip():
            errors.append(self.create_error(
                "Field 'triggerOperator' cannot be empty",
                field='triggerOperator'
            ))
            return errors
        
        if trigger_operator not in self.VALID_TRIGGER_OPERATORS:
            valid_values = "', '".join(self.VALID_TRIGGER_OPERATORS)
            errors.append(self.create_error(
                f"Field 'triggerOperator' has invalid value '{trigger_operator}'. "
                f"Must be one of: '{valid_values}'",
                field='triggerOperator'
            ))
        
        return errors
    
    def _validate_trigger_threshold(self, rule_data: dict) -> List[Dict]:
        """Validate triggerThreshold field"""
        errors = []
        
        trigger_threshold = rule_data.get('triggerThreshold')
        if trigger_threshold is None:
            # Missing triggerThreshold would be caught by schema validator
            return errors
        
        # Check type
        if not isinstance(trigger_threshold, int):
            errors.append(self.create_error(
                f"Field 'triggerThreshold' must be an integer, got {type(trigger_threshold).__name__}",
                field='triggerThreshold'
            ))
            return errors
        
        # Check range
        if trigger_threshold < 0 or trigger_threshold > self.MAX_TRIGGER_THRESHOLD:
            errors.append(self.create_error(
                f"Field 'triggerThreshold' must be between 0 and {self.MAX_TRIGGER_THRESHOLD}, "
                f"got {trigger_threshold}",
                field='triggerThreshold'
            ))
        
        return errors
    
    def _validate_tactics(self, rule_data: dict) -> List[Dict]:
        """Validate tactics field against MITRE ATT&CK v13"""
        errors = []
        
        tactics = rule_data.get('tactics')
        if not tactics:
            # Tactics is mandatory according to documentation
            return errors  # Would be caught by schema validator if truly required
        
        if not isinstance(tactics, list):
            errors.append(self.create_error(
                f"Field 'tactics' must be a list, got {type(tactics).__name__}",
                field='tactics'
            ))
            return errors
        
        # Validate each tactic
        for idx, tactic in enumerate(tactics):
            if not isinstance(tactic, str):
                errors.append(self.create_error(
                    f"Tactic at index {idx} must be a string, got {type(tactic).__name__}",
                    field=f'tactics[{idx}]'
                ))
                continue
            
            # Check if tactic is in valid list
            if tactic not in self.VALID_TACTICS:
                # Check if it might be a spacing issue
                tactic_no_space = tactic.replace(" ", "")
                if tactic_no_space in self.VALID_TACTICS:
                    errors.append(self.create_error(
                        f"Tactic '{tactic}' contains spaces. "
                        f"MITRE ATT&CK tactics must not contain spaces. Use '{tactic_no_space}' instead",
                        field=f'tactics[{idx}]'
                    ))
                else:
                    valid_list = ", ".join(self.VALID_TACTICS)
                    errors.append(self.create_error(
                        f"Tactic '{tactic}' is not a valid MITRE ATT&CK v13 tactic. "
                        f"Valid tactics are: {valid_list}",
                        field=f'tactics[{idx}]'
                    ))
        
        return errors
    
    def _validate_relevant_techniques(self, rule_data: dict) -> List[Dict]:
        """Validate relevantTechniques field format"""
        errors = []
        
        techniques = rule_data.get('relevantTechniques')
        if not techniques:
            # relevantTechniques is mandatory according to documentation
            return errors  # Would be caught by schema validator if truly required
        
        if not isinstance(techniques, list):
            errors.append(self.create_error(
                f"Field 'relevantTechniques' must be a list, got {type(techniques).__name__}",
                field='relevantTechniques'
            ))
            return errors
        
        # Validate each technique
        for idx, technique in enumerate(techniques):
            if not isinstance(technique, str):
                errors.append(self.create_error(
                    f"Technique at index {idx} must be a string, got {type(technique).__name__}",
                    field=f'relevantTechniques[{idx}]'
                ))
                continue
            
            # Validate format: T#### or T####.### (T1000-T1999 range)
            # Main technique pattern: T followed by 4 digits
            # Sub-technique pattern: T####.### (up to 3 digits after decimal)
            
            if not self._is_valid_technique_format(technique):
                errors.append(self.create_error(
                    f"Technique '{technique}' has invalid format. "
                    f"Must be 'T####' (e.g., T1078) or 'T####.###' (e.g., T1078.001) "
                    f"where #### is in range 1000-1999",
                    field=f'relevantTechniques[{idx}]'
                ))
        
        return errors
    
    def _is_valid_technique_format(self, technique: str) -> bool:
        """
        Check if technique follows valid MITRE ATT&CK format.
        Valid formats: T1234 or T1234.001
        Technique ID range: T1000-T1999
        """
        # Pattern: T followed by 4 digits, optionally followed by . and 1-3 digits
        pattern = r'^T(\d{4})(?:\.(\d{1,3}))?$'
        match = re.match(pattern, technique)
        
        if not match:
            return False
        
        # Extract technique number
        technique_num = int(match.group(1))
        
        # Validate range (T1000-T1999)
        if technique_num < 1000 or technique_num > 1999:
            return False
        
        # If sub-technique exists, validate it
        if match.group(2):
            sub_technique_num = int(match.group(2))
            # Sub-techniques typically range from 001-999
            if sub_technique_num < 1 or sub_technique_num > 999:
                return False
        
        return True
    
    def _validate_name_constraints(self, rule_data: dict) -> List[Dict]:
        """Validate name field constraints"""
        errors = []
        
        name = rule_data.get('name')
        if not name:
            # Missing name would be caught by schema validator
            return errors
        
        if not isinstance(name, str):
            return errors  # Type error would be caught by schema validator
        
        # Check maximum length
        if len(name) > self.MAX_NAME_LENGTH:
            errors.append(self.create_error(
                f"Field 'name' exceeds maximum length of {self.MAX_NAME_LENGTH} characters. "
                f"Current length: {len(name)} characters",
                field='name'
            ))
        
        # Check if name ends with a period
        if name.endswith('.'):
            errors.append(self.create_error(
                f"Field 'name' must not end with a period",
                field='name'
            ))
        
        return errors
    
    def _validate_description_constraints(self, rule_data: dict) -> List[Dict]:
        """Validate description field constraints"""
        errors = []
        
        description = rule_data.get('description')
        if not description:
            # Missing description would be caught by schema validator
            return errors
        
        if not isinstance(description, str):
            return errors  # Type error would be caught by schema validator
        
        # Check maximum length
        if len(description) > self.MAX_DESCRIPTION_LENGTH:
            errors.append(self.create_error(
                f"Field 'description' exceeds maximum length of {self.MAX_DESCRIPTION_LENGTH} characters. "
                f"Current length: {len(description)} characters",
                field='description'
            ))
        
        # Skip content validation per user request
        
        return errors
    
    def _validate_query_constraints(self, rule_data: dict) -> List[Dict]:
        """Validate query field constraints"""
        errors = []
        
        query = rule_data.get('query')
        if not query:
            # Missing query would be caught by schema validator
            return errors
        
        if not isinstance(query, str):
            return errors  # Type error would be caught by schema validator
        
        # Check maximum length
        if len(query) > self.MAX_QUERY_LENGTH:
            errors.append(self.create_error(
                f"Field 'query' exceeds maximum length of {self.MAX_QUERY_LENGTH} characters. "
                f"Current length: {len(query)} characters. "
                f"Consider moving static lists to watchlists or using KQL functions.",
                field='query'
            ))
        
        return errors
    
    def _validate_version(self, rule_data: dict) -> List[Dict]:
        """Validate version field format"""
        errors = []
        
        version = rule_data.get('version')
        if not version or not version.strip():
            errors.append(self.create_error(
                "Field 'version' cannot be empty",
                field='version'
            ))
            return errors
        
        if not isinstance(version, str):
            errors.append(self.create_error(
                f"Field 'version' must be a string, got {type(version).__name__}",
                field='version'
            ))
            return errors
        
        # Validate semantic versioning format: a.b.c
        # Where a = major, b = minor, c = patch
        version_pattern = r'^\d+\.\d+\.\d+$'
        
        if not re.match(version_pattern, version):
            errors.append(self.create_error(
                f"Field 'version' has invalid format '{version}'. "
                f"Must follow semantic versioning format 'a.b.c' (e.g., '1.0.0', '1.2.3')",
                field='version'
            ))
        
        return errors
    
    def _validate_event_grouping(self, rule_data: dict) -> List[Dict]:
        """Validate eventGroupingSettings field"""
        errors = []
        
        event_grouping = rule_data.get('eventGroupingSettings')
        if not event_grouping:
            # Optional field
            return errors
        
        if not isinstance(event_grouping, dict):
            errors.append(self.create_error(
                f"Field 'eventGroupingSettings' must be a dictionary, got {type(event_grouping).__name__}",
                field='eventGroupingSettings'
            ))
            return errors
        
        aggregation_kind = event_grouping.get('aggregationKind')
        if aggregation_kind:
            if aggregation_kind not in self.VALID_AGGREGATION_KINDS:
                valid_values = "', '".join(self.VALID_AGGREGATION_KINDS)
                errors.append(self.create_error(
                    f"Field 'eventGroupingSettings.aggregationKind' has invalid value '{aggregation_kind}'. "
                    f"Must be one of: '{valid_values}'",
                    field='eventGroupingSettings.aggregationKind'
                ))
        
        return errors
    
    def _validate_entity_mappings_limits(self, rule_data: dict) -> List[Dict]:
        """Validate entity mappings count limits"""
        errors = []
        
        entity_mappings = rule_data.get('entityMappings')
        if not entity_mappings:
            # Optional field
            return errors
        
        if not isinstance(entity_mappings, list):
            return errors  # Type error would be caught elsewhere
        
        # Check maximum number of entity mappings
        if len(entity_mappings) > self.MAX_ENTITY_MAPPINGS:
            errors.append(self.create_error(
                f"Field 'entityMappings' exceeds maximum of {self.MAX_ENTITY_MAPPINGS} mappings. "
                f"Current count: {len(entity_mappings)} mappings",
                field='entityMappings'
            ))
        
        # Check field mappings per entity
        for idx, entity in enumerate(entity_mappings):
            if not isinstance(entity, dict):
                continue
            
            field_mappings = entity.get('fieldMappings')
            if not field_mappings or not isinstance(field_mappings, list):
                continue
            
            if len(field_mappings) > self.MAX_FIELD_MAPPINGS_PER_ENTITY:
                entity_type = entity.get('entityType', 'unknown')
                errors.append(self.create_error(
                    f"Entity mapping '{entity_type}' at index {idx} exceeds maximum of "
                    f"{self.MAX_FIELD_MAPPINGS_PER_ENTITY} field mappings. "
                    f"Current count: {len(field_mappings)} field mappings",
                    field=f'entityMappings[{idx}].fieldMappings'
                ))
        
        return errors
    
    def _validate_custom_details(self, rule_data: dict) -> List[Dict]:
        """Validate customDetails field limits"""
        errors = []
        
        custom_details = rule_data.get('customDetails')
        if not custom_details:
            # Optional field
            return errors
        
        if not isinstance(custom_details, dict):
            errors.append(self.create_error(
                f"Field 'customDetails' must be a dictionary, got {type(custom_details).__name__}",
                field='customDetails'
            ))
            return errors
        
        # Check maximum number of custom details (key/value pairs)
        if len(custom_details) > self.MAX_CUSTOM_DETAILS:
            errors.append(self.create_error(
                f"Field 'customDetails' exceeds maximum of {self.MAX_CUSTOM_DETAILS} key/value pairs. "
                f"Current count: {len(custom_details)} pairs",
                field='customDetails'
            ))
        
        return errors
    
    def _validate_alert_details_override(self, rule_data: dict) -> List[Dict]:
        """Validate alertDetailsOverride field constraints"""
        errors = []
        
        alert_override = rule_data.get('alertDetailsOverride')
        if not alert_override:
            # Optional field
            return errors
        
        if not isinstance(alert_override, dict):
            errors.append(self.create_error(
                f"Field 'alertDetailsOverride' must be a dictionary, got {type(alert_override).__name__}",
                field='alertDetailsOverride'
            ))
            return errors
        
        # Validate alertDisplayNameFormat
        display_name = alert_override.get('alertDisplayNameFormat')
        if display_name:
            errors.extend(self._validate_alert_format_field(
                display_name,
                'alertDisplayNameFormat',
                self.MAX_ALERT_NAME_LENGTH
            ))
        
        # Validate alertDescriptionFormat
        description = alert_override.get('alertDescriptionFormat')
        if description:
            errors.extend(self._validate_alert_format_field(
                description,
                'alertDescriptionFormat',
                self.MAX_ALERT_DESCRIPTION_LENGTH
            ))
        
        return errors
    
    def _validate_alert_format_field(self, value: str, field_name: str, max_length: int) -> List[Dict]:
        """Validate alert format fields (name and description)"""
        errors = []
        
        if not isinstance(value, str):
            errors.append(self.create_error(
                f"Field 'alertDetailsOverride.{field_name}' must be a string, "
                f"got {type(value).__name__}",
                field=f'alertDetailsOverride.{field_name}'
            ))
            return errors
        
        # Check maximum length
        if len(value) > max_length:
            errors.append(self.create_error(
                f"Field 'alertDetailsOverride.{field_name}' exceeds maximum length of "
                f"{max_length} characters. Current length: {len(value)} characters",
                field=f'alertDetailsOverride.{field_name}'
            ))
        
        # Count parameters ({{columnName}} format)
        # Pattern to match {{columnName}} with optional whitespace
        param_pattern = r'\{\{\s*\w+\s*\}\}'
        parameters = re.findall(param_pattern, value)
        
        if len(parameters) > self.MAX_ALERT_PARAMETERS:
            errors.append(self.create_error(
                f"Field 'alertDetailsOverride.{field_name}' exceeds maximum of "
                f"{self.MAX_ALERT_PARAMETERS} parameters. Current count: {len(parameters)} parameters. "
                f"Parameters must be in format {{{{columnName}}}}",
                field=f'alertDetailsOverride.{field_name}'
            ))
        
        # Validate parameter format (no leading/trailing spaces inside braces)
        for param in parameters:
            # Extract content between {{ and }}
            inner = param[2:-2]
            if inner != inner.strip():
                errors.append(self.create_error(
                    f"Parameter '{param}' in 'alertDetailsOverride.{field_name}' has leading or trailing "
                    f"whitespace. Must be in format {{{{columnName}}}} without spaces inside braces",
                    field=f'alertDetailsOverride.{field_name}'
                ))
                break  # Only report once per field
        
        return errors
    
    def _validate_grouping_configuration(self, rule_data: dict) -> List[Dict]:
        """Validate grouping configuration and lookback duration"""
        errors = []
        
        incident_config = rule_data.get('incidentConfiguration', {})
        if not isinstance(incident_config, dict):
            errors.append(self.create_error(
                "Field 'incidentConfiguration' must be a dictionary",
                field='incidentConfiguration'
            ))
            return errors
        
        grouping_config = incident_config.get('groupingConfiguration', {})
        if not isinstance(grouping_config, dict):
            errors.append(self.create_error(
                "Field 'groupingConfiguration' must be a dictionary",
                field='incidentConfiguration.groupingConfiguration'
            ))
            return errors
        
        enabled = grouping_config.get('enabled')
        if enabled:
            # Validate lookbackDuration when grouping is enabled
            lookback = grouping_config.get('lookbackDuration')
            if not lookback:
                errors.append(self.create_error(
                    "When grouping is enabled, lookbackDuration must be specified",
                    field='incidentConfiguration.groupingConfiguration.lookbackDuration'
                ))
                return errors
            
            # Convert lookback duration to hours for validation
            try:
                hours = self._parse_duration_to_hours(lookback)
                if hours < 3:
                    errors.append(self.create_error(
                        f"lookbackDuration '{lookback}' is too short. Minimum duration is 3h",
                        field='incidentConfiguration.groupingConfiguration.lookbackDuration'
                    ))
                elif hours > 24:
                    errors.append(self.create_error(
                        f"lookbackDuration '{lookback}' is too long. Maximum duration is 24h",
                        field='incidentConfiguration.groupingConfiguration.lookbackDuration'
                    ))
            except ValueError as e:
                errors.append(self.create_error(
                    f"Invalid lookbackDuration format: {str(e)}",
                    field='incidentConfiguration.groupingConfiguration.lookbackDuration'
                ))
        
        return errors

    def _parse_duration_to_hours(self, duration: str) -> float:
        """Convert duration string to hours"""
        if not isinstance(duration, str):
            raise ValueError("Duration must be a string")
        
        # Remove whitespace and convert to lowercase
        duration = duration.strip().lower()
        
        if not duration:
            raise ValueError("Duration cannot be empty")
        
        # Handle different time units
        if duration.endswith('h'):
            return float(duration[:-1])
        elif duration.endswith('d'):
            return float(duration[:-1]) * 24
        elif duration.endswith('m'):
            return float(duration[:-1]) / 60
        else:
            raise ValueError("Duration must end with 'm', 'h', or 'd'")
