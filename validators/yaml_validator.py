"""
YAML Validator
Validates YAML formatting, whitespace consistency, and duplicate keys.
"""

from pathlib import Path
from typing import List, Dict, Set, Tuple
import yaml

from .base_validator import BaseValidator


class YAMLValidator(BaseValidator):
    """Validates YAML formatting and structure"""
    
    @property
    def validator_name(self) -> str:
        return "YAML Validator"
    
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """Validate YAML formatting and structure"""
        errors = []
        
        # Read raw file content for formatting checks
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                raw_content = f.read()
        except Exception as e:
            errors.append(self.create_error(
                f"Failed to read file for validation: {str(e)}"
            ))
            return errors
        
        # Check for tabs
        tab_errors = self._check_for_tabs(raw_content)
        errors.extend(tab_errors)
        
        # Check indentation consistency
        indent_errors = self._check_indentation_consistency(raw_content)
        errors.extend(indent_errors)
        
        # Check for duplicate keys
        duplicate_errors = self._check_duplicate_keys(raw_content, file_path)
        errors.extend(duplicate_errors)
        
        # Check for trailing whitespace
        trailing_errors = self._check_trailing_whitespace(raw_content)
        errors.extend(trailing_errors)
        
        # Check for empty lines with whitespace
        empty_line_errors = self._check_empty_lines_with_whitespace(raw_content)
        errors.extend(empty_line_errors)
        
        return errors
    
    def _check_for_tabs(self, content: str) -> List[Dict]:
        """Check for tab characters in YAML content"""
        errors = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, start=1):
            if '\t' in line:
                # Find all tab positions
                tab_positions = [i for i, char in enumerate(line) if char == '\t']
                
                errors.append(self.create_error(
                    f"Line {line_num}: Tab character found at position(s) {tab_positions}. "
                    f"YAML spec requires spaces for indentation, not tabs."
                ))
        
        return errors
    
    def _check_indentation_consistency(self, content: str) -> List[Dict]:
        """Check for consistent indentation spacing"""
        errors = []
        lines = content.split('\n')
        
        # Collect indentation levels (ignoring empty lines and comments)
        indent_levels = []
        
        for line_num, line in enumerate(lines, start=1):
            # Skip empty lines
            if not line.strip():
                continue
            
            # Skip comment-only lines
            if line.strip().startswith('#'):
                continue
            
            # Calculate indentation (number of leading spaces)
            indent = len(line) - len(line.lstrip(' '))
            
            # Only consider lines with indentation
            if indent > 0:
                indent_levels.append((line_num, indent))
        
        if not indent_levels:
            return errors
        
        # Determine the common indentation unit (2 or 4 spaces typically)
        # Find the GCD of all non-zero indentation levels
        indents = set(indent for _, indent in indent_levels)
        indents.discard(0)
        
        if indents:
            indent_unit = self._find_gcd_of_set(indents)
            
            # Check if all indentation levels are multiples of the unit
            inconsistent_lines = []
            for line_num, indent in indent_levels:
                if indent % indent_unit != 0:
                    inconsistent_lines.append((line_num, indent))
            
            if inconsistent_lines and indent_unit > 1:
                for line_num, indent in inconsistent_lines[:5]:  # Report first 5
                    errors.append(self.create_warning(
                        f"Line {line_num}: Indentation of {indent} spaces is not a multiple of "
                        f"the detected indent unit ({indent_unit} spaces). "
                        f"This may indicate inconsistent indentation."
                    ))
                
                if len(inconsistent_lines) > 5:
                    errors.append(self.create_warning(
                        f"Found {len(inconsistent_lines) - 5} additional lines with inconsistent indentation."
                    ))
        
        return errors
    
    def _find_gcd_of_set(self, numbers: Set[int]) -> int:
        """Find the GCD of a set of numbers"""
        from math import gcd
        from functools import reduce
        
        if not numbers:
            return 1
        
        return reduce(gcd, numbers)
    
    def _check_duplicate_keys(self, content: str, file_path: Path) -> List[Dict]:
        """Check for duplicate keys at any level in the YAML"""
        errors = []
        
        try:
            # Use a custom loader to detect duplicate keys
            duplicates = self._find_duplicate_keys_with_loader(content)
            
            for key_path, line_numbers in duplicates:
                lines_str = ', '.join(map(str, sorted(line_numbers)))
                errors.append(self.create_error(
                    f"Duplicate key '{key_path}' found at lines: {lines_str}. "
                    f"YAML does not allow duplicate keys at the same level."
                ))
        
        except yaml.YAMLError as e:
            # YAML parsing error - but this should be caught by yaml_loader already
            pass
        except Exception as e:
            errors.append(self.create_warning(
                f"Could not check for duplicate keys: {str(e)}"
            ))
        
        return errors
    
    def _find_duplicate_keys_with_loader(self, content: str) -> List[Tuple[str, Set[int]]]:
        """
        Find duplicate keys by parsing YAML with a custom constructor.
        Returns list of (key_path, set_of_line_numbers)
        """
        duplicates = []
        
        class DuplicateKeyLoader(yaml.SafeLoader):
            pass
        
        def check_duplicates(loader, node, deep=False, prefix=''):
            """Check for duplicate keys in mapping nodes"""
            mapping = {}
            duplicates_local = []
            
            for key_node, value_node in node.value:
                # Get the key
                key = loader.construct_object(key_node, deep=deep)
                
                # Get line number
                line_num = key_node.start_mark.line + 1
                
                # Build full key path
                full_key = f"{prefix}.{key}" if prefix else str(key)
                
                # Check if key already exists
                if key in mapping:
                    # Duplicate found
                    existing_line = mapping[key]
                    duplicates_local.append((full_key, {existing_line, line_num}))
                else:
                    mapping[key] = line_num
                
                # Recursively check nested mappings
                if isinstance(value_node, yaml.MappingNode):
                    nested_dups = check_duplicates(loader, value_node, deep, full_key)
                    duplicates_local.extend(nested_dups)
            
            return duplicates_local
        
        def mapping_constructor(loader, node):
            """Custom constructor that checks for duplicates"""
            # Check for duplicates at this level
            dups = check_duplicates(loader, node)
            duplicates.extend(dups)
            
            # Return normal mapping
            return loader.construct_mapping(node)
        
        # Override the mapping constructor
        DuplicateKeyLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            mapping_constructor
        )
        
        # Parse the YAML
        try:
            yaml.load(content, Loader=DuplicateKeyLoader)
        except yaml.YAMLError:
            # If YAML is invalid, it will be caught by other validators
            pass
        
        return duplicates
    
    def _check_trailing_whitespace(self, content: str) -> List[Dict]:
        """Check for trailing whitespace on lines"""
        errors = []
        lines = content.split('\n')
        
        trailing_lines = []
        for line_num, line in enumerate(lines, start=1):
            # Check if line has trailing whitespace (but is not empty)
            if line and line != line.rstrip():
                trailing_lines.append(line_num)
        
        if trailing_lines:
            # Report as a single warning if multiple lines
            if len(trailing_lines) <= 5:
                lines_str = ', '.join(map(str, trailing_lines))
                errors.append(self.create_warning(
                    f"Trailing whitespace found on line(s): {lines_str}. "
                    f"Consider removing trailing spaces for cleaner formatting."
                ))
            else:
                errors.append(self.create_warning(
                    f"Trailing whitespace found on {len(trailing_lines)} lines "
                    f"(first 5: {', '.join(map(str, trailing_lines[:5]))}). "
                    f"Consider removing trailing spaces for cleaner formatting."
                ))
        
        return errors
    
    def _check_empty_lines_with_whitespace(self, content: str) -> List[Dict]:
        """Check for empty lines that contain only whitespace"""
        errors = []
        lines = content.split('\n')
        
        whitespace_lines = []
        for line_num, line in enumerate(lines, start=1):
            # Check if line is not empty but contains only whitespace
            if line and not line.strip():
                whitespace_lines.append(line_num)
        
        if whitespace_lines:
            if len(whitespace_lines) <= 5:
                lines_str = ', '.join(map(str, whitespace_lines))
                errors.append(self.create_warning(
                    f"Empty line(s) with whitespace found at: {lines_str}. "
                    f"Consider using completely empty lines."
                ))
            else:
                errors.append(self.create_warning(
                    f"Found {len(whitespace_lines)} empty lines with whitespace "
                    f"(first 5: {', '.join(map(str, whitespace_lines[:5]))}). "
                    f"Consider using completely empty lines."
                ))
        
        return errors






