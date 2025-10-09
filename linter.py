#!/usr/bin/env python3
"""
Sentinel Detection Linter
Main entry point for validating Microsoft Sentinel Analytics Rules in YAML format.
"""

import sys
import argparse
import json
from pathlib import Path
from typing import List, Dict
from datetime import datetime

from validators.guid_validator import GuidValidator
from validators.schema_validator import SchemaValidator
from validators.entity_validator import EntityValidator
from validators.timing_validator import TimingValidator
from validators.kql_validator import KQLValidator
from validators.asim_field_validator import ASIMFieldValidator
from validators.sentinel_constraints_validator import SentinelConstraintsValidator
from utils.yaml_loader import load_yaml_file, YAMLLoadError
from utils.file_scanner import scan_yaml_files
from config.schema_definition import SENTINEL_SCHEMA


class ValidationResult:
    """Container for validation results"""
    
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.errors = []
        self.warnings = []
        self.passed = True
    
    def add_error(self, validator_name: str, message: str, field: str = None):
        """Add an error to the results"""
        self.errors.append({
            'validator': validator_name,
            'severity': 'error',
            'message': message,
            'field': field
        })
        self.passed = False
    
    def add_warning(self, validator_name: str, message: str, field: str = None):
        """Add a warning to the results"""
        self.warnings.append({
            'validator': validator_name,
            'severity': 'warning',
            'message': message,
            'field': field
        })
    
    def get_summary(self) -> Dict:
        """Get summary of validation results"""
        return {
            'file': str(self.file_path),
            'status': 'passed' if self.passed else 'failed',
            'errors': len(self.errors),
            'warnings': len(self.warnings)
        }


class SentinelLinter:
    """Main linter orchestrator"""
    
    def __init__(self, kql_schema: dict = None, enable_kql_validation: bool = True):
        """
        Initialize the linter with validators.
        
        Args:
            kql_schema: Optional schema configuration for KQL semantic validation
            enable_kql_validation: Whether to enable KQL validation (requires .NET)
        """
        self.validators = []
        
        # Always-enabled validators (order matters for logical progression)
        self.validators.append(GuidValidator())
        self.validators.append(SchemaValidator())
        self.validators.append(SentinelConstraintsValidator())  # NEW: Validates Microsoft requirements
        self.validators.append(EntityValidator())
        self.validators.append(ASIMFieldValidator())
        self.validators.append(TimingValidator())
        
        # Optional KQL validator (may not be available if .NET not installed)
        self.kql_validator = None
        if enable_kql_validation:
            try:
                self.kql_validator = KQLValidator(kql_schema)
                self.validators.append(self.kql_validator)
            except Exception as e:
                print(f"WARNING: KQL validation disabled. Reason: {e}")
                print("Install .NET SDK 6+ and build Kusto.Language.dll to enable KQL validation.")
    
    def validate_file(self, file_path: Path, all_yaml_files: List[Path] = None) -> ValidationResult:
        """
        Validate a single YAML file.
        
        Args:
            file_path: Path to the YAML file
            all_yaml_files: List of all YAML files for uniqueness checking
        
        Returns:
            ValidationResult object
        """
        result = ValidationResult(file_path)
        
        # Load YAML file
        try:
            rule_data = load_yaml_file(file_path)
        except YAMLLoadError as e:
            result.add_error('YAML Parser', str(e))
            return result
        except Exception as e:
            result.add_error('File Loader', f'Failed to load file: {str(e)}')
            return result
        
        # Run all validators
        for validator in self.validators:
            try:
                errors = validator.validate(rule_data, file_path, all_yaml_files)
                
                for error in errors:
                    severity = error.get('severity', 'error').lower()
                    validator_name = validator.validator_name
                    message = error.get('message', 'Unknown error')
                    field = error.get('field')
                    
                    if severity == 'warning':
                        result.add_warning(validator_name, message, field)
                    else:
                        result.add_error(validator_name, message, field)
                        
            except Exception as e:
                result.add_error(
                    validator.validator_name,
                    f'Validator crashed: {str(e)}'
                )
        
        return result
    
    def validate_directory(self, directory: Path) -> List[ValidationResult]:
        """
        Validate all YAML files in a directory.
        
        Args:
            directory: Path to directory containing YAML files
        
        Returns:
            List of ValidationResult objects
        """
        yaml_files = scan_yaml_files(directory)
        
        if not yaml_files:
            print(f"No YAML files found in {directory}")
            return []
        
        results = []
        for file_path in yaml_files:
            result = self.validate_file(file_path, yaml_files)
            results.append(result)
        
        return results


def print_console_output(results: List[ValidationResult], verbose: bool = False):
    """Print validation results to console"""
    
    total_files = len(results)
    passed_files = sum(1 for r in results if r.passed)
    failed_files = total_files - passed_files
    total_errors = sum(len(r.errors) for r in results)
    total_warnings = sum(len(r.warnings) for r in results)
    
    print("\n" + "="*70)
    print("SENTINEL DETECTION LINTER - VALIDATION RESULTS")
    print("="*70 + "\n")
    
    for result in results:
        status_symbol = "[PASS]" if result.passed else "[FAIL]"
        print(f"{status_symbol} {result.file_path.name}")
        
        if result.errors or verbose:
            for error in result.errors:
                field_info = f" (field: {error['field']})" if error['field'] else ""
                print(f"  [ERROR] {error['validator']}: {error['message']}{field_info}")
        
        if result.warnings and verbose:
            for warning in result.warnings:
                field_info = f" (field: {warning['field']})" if warning['field'] else ""
                print(f"  [WARN]  {warning['validator']}: {warning['message']}{field_info}")
        
        if result.errors or (result.warnings and verbose):
            print()
    
    print("="*70)
    print(f"Summary: {passed_files}/{total_files} files passed")
    print(f"         {total_errors} errors, {total_warnings} warnings")
    print("="*70 + "\n")
    
    return failed_files == 0


def print_json_output(results: List[ValidationResult]):
    """Print validation results as JSON"""
    
    output = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'summary': {
            'total_files': len(results),
            'passed': sum(1 for r in results if r.passed),
            'failed': sum(1 for r in results if not r.passed),
            'total_errors': sum(len(r.errors) for r in results),
            'total_warnings': sum(len(r.warnings) for r in results)
        },
        'results': []
    }
    
    for result in results:
        output['results'].append({
            'file': str(result.file_path),
            'status': 'passed' if result.passed else 'failed',
            'errors': result.errors,
            'warnings': result.warnings
        })
    
    print(json.dumps(output, indent=2))
    
    return output['summary']['failed'] == 0


def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(
        description='Validate Microsoft Sentinel Analytics Rules in YAML format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Validate a single file:
    python linter.py detection.yaml
  
  Validate all files in a directory:
    python linter.py --directory ./detections/
  
  Output results as JSON:
    python linter.py detection.yaml --output json
  
  Verbose output with warnings:
    python linter.py detection.yaml --verbose
  
  Disable KQL validation:
    python linter.py detection.yaml --no-kql-validation
        """
    )
    
    parser.add_argument(
        'file',
        nargs='?',
        type=Path,
        help='Path to YAML file to validate'
    )
    
    parser.add_argument(
        '-d', '--directory',
        type=Path,
        help='Validate all YAML files in directory'
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['console', 'json'],
        default='console',
        help='Output format (default: console)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show warnings and additional details'
    )
    
    parser.add_argument(
        '--no-kql-validation',
        action='store_true',
        help='Disable KQL validation (useful if .NET not available)'
    )
    
    parser.add_argument(
        '--schema',
        type=Path,
        help='Path to custom schema configuration JSON file'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and not args.directory:
        parser.error('Must specify either a file or --directory')
    
    if args.file and args.directory:
        parser.error('Cannot specify both file and --directory')
    
    # Load custom schema if provided
    kql_schema = None
    if args.schema:
        try:
            with open(args.schema, 'r') as f:
                kql_schema = json.load(f)
        except Exception as e:
            print(f"ERROR: Failed to load schema file: {e}")
            return 1
    
    # Initialize linter
    enable_kql = not args.no_kql_validation
    linter = SentinelLinter(kql_schema=kql_schema, enable_kql_validation=enable_kql)
    
    # Validate files
    results = []
    if args.file:
        if not args.file.exists():
            print(f"ERROR: File not found: {args.file}")
            return 1
        result = linter.validate_file(args.file)
        results = [result]
    else:
        if not args.directory.exists():
            print(f"ERROR: Directory not found: {args.directory}")
            return 1
        results = linter.validate_directory(args.directory)
    
    # Output results
    if args.output == 'json':
        success = print_json_output(results)
    else:
        success = print_console_output(results, args.verbose)
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
