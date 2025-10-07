# Contributing to Sentinel Detection Linter

Thank you for your interest in contributing to the Sentinel Detection Linter! This document provides guidelines for extending the linter with new validators and improvements.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Project Architecture](#project-architecture)
3. [Adding a New Validator](#adding-a-new-validator)
4. [Coding Standards](#coding-standards)
5. [Testing](#testing)
6. [Submitting Changes](#submitting-changes)

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Set up the development environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
python setup.py full-setup
```

## Project Architecture

### Directory Structure

```
sentinel-detection-linter/
|-- validators/           # Validation logic
|-- utils/               # Helper utilities
|-- config/              # Configuration and constants
|-- examples/            # Example files
```

### Key Components

1. **BaseValidator**: Abstract base class all validators inherit from
2. **ValidationError**: Standard error format
3. **SentinelLinter**: Orchestrates all validators
4. **YAML Loader**: Safely loads YAML files
5. **File Scanner**: Finds YAML files in directories

## Adding a New Validator

### Step 1: Create Validator Class

Create a new file in `validators/`:

```python
# validators/my_validator.py

from pathlib import Path
from typing import List, Dict
from .base_validator import BaseValidator


class MyValidator(BaseValidator):
    """
    Brief description of what this validator checks.
    """
    
    @property
    def validator_name(self) -> str:
        """Human-readable name displayed in output"""
        return "My Custom Validator"
    
    def validate(self, rule_data: dict, file_path: Path, 
                 all_files: List[Path] = None) -> List[Dict]:
        """
        Validate the rule data.
        
        Args:
            rule_data: Parsed YAML data as dictionary
            file_path: Path to the file being validated
            all_files: List of all YAML files (for cross-file checks)
        
        Returns:
            List of error/warning dictionaries
        """
        errors = []
        
        # Your validation logic here
        if 'required_field' not in rule_data:
            errors.append(self.create_error(
                "Missing required field 'required_field'",
                field='required_field'
            ))
        
        return errors
```

### Step 2: Register the Validator

Add your validator to `linter.py`:

```python
from validators.my_validator import MyValidator

# In SentinelLinter.__init__:
self.validators.append(MyValidator())
```

### Step 3: Update __init__.py

Add your validator to `validators/__init__.py`:

```python
from .my_validator import MyValidator

__all__ = [
    # ... existing validators
    'MyValidator'
]
```

## Validator Examples

### Example 1: Simple Field Check

```python
class RequiredFieldValidator(BaseValidator):
    @property
    def validator_name(self) -> str:
        return "Required Field Validator"
    
    def validate(self, rule_data: dict, file_path: Path, 
                 all_files: List[Path] = None) -> List[Dict]:
        errors = []
        
        required_fields = ['id', 'name', 'query']
        
        for field in required_fields:
            if field not in rule_data:
                errors.append(self.create_error(
                    f"Missing required field '{field}'",
                    field=field
                ))
        
        return errors
```

### Example 2: Cross-Field Validation

```python
class LogicValidator(BaseValidator):
    @property
    def validator_name(self) -> str:
        return "Logic Validator"
    
    def validate(self, rule_data: dict, file_path: Path, 
                 all_files: List[Path] = None) -> List[Dict]:
        errors = []
        
        # Check if suppressionEnabled is true but suppressionDuration is missing
        if rule_data.get('suppressionEnabled') == True:
            if 'suppressionDuration' not in rule_data:
                errors.append(self.create_error(
                    "Field 'suppressionDuration' is required when suppressionEnabled is true",
                    field='suppressionDuration'
                ))
        
        return errors
```

### Example 3: Pattern Validation

```python
import re

class NamingConventionValidator(BaseValidator):
    @property
    def validator_name(self) -> str:
        return "Naming Convention Validator"
    
    def validate(self, rule_data: dict, file_path: Path, 
                 all_files: List[Path] = None) -> List[Dict]:
        errors = []
        
        name = rule_data.get('name')
        if name:
            # Check naming convention: Must be alphanumeric with underscores
            pattern = r'^[A-Za-z0-9_]+$'
            if not re.match(pattern, name):
                errors.append(self.create_warning(
                    f"Field 'name' should follow naming convention: {pattern}",
                    field='name'
                ))
        
        return errors
```

### Example 4: Cross-File Validation

```python
class DuplicateNameValidator(BaseValidator):
    @property
    def validator_name(self) -> str:
        return "Duplicate Name Validator"
    
    def validate(self, rule_data: dict, file_path: Path, 
                 all_files: List[Path] = None) -> List[Dict]:
        errors = []
        
        if not all_files:
            return errors
        
        current_name = rule_data.get('name')
        if not current_name:
            return errors
        
        # Check for duplicate names
        from utils.yaml_loader import load_yaml_file
        
        for other_file in all_files:
            if other_file == file_path:
                continue
            
            try:
                other_data = load_yaml_file(other_file)
                other_name = other_data.get('name')
                
                if other_name == current_name:
                    errors.append(self.create_error(
                        f"Name '{current_name}' is not unique. "
                        f"Also found in: {other_file.name}",
                        field='name'
                    ))
                    break
            except Exception:
                continue
        
        return errors
```

## Helper Methods

The `BaseValidator` class provides helper methods:

### create_error()

Creates an error dictionary:

```python
self.create_error(
    "Error message",
    field='field_name',  # Optional
    custom_key='custom_value'  # Optional extra data
)
```

### create_warning()

Creates a warning dictionary:

```python
self.create_warning(
    "Warning message",
    field='field_name'
)
```

## Coding Standards

### Python Style

Follow PEP 8 guidelines:

- Use 4 spaces for indentation
- Maximum line length: 100 characters
- Use descriptive variable names
- Add docstrings to all classes and methods

### Type Hints

Use type hints for all function parameters and return values:

```python
def validate(self, rule_data: dict, file_path: Path, 
             all_files: List[Path] = None) -> List[Dict]:
    pass
```

### Error Messages

Write clear, actionable error messages:

Good:
```python
"Field 'queryFrequency' has invalid format: '5x'. Expected format: <number><unit> where unit is 'm', 'h', or 'd'"
```

Bad:
```python
"Invalid queryFrequency"
```

### Comments

Add comments for complex logic:

```python
# Convert time string to minutes for comparison
# Supported formats: 5m (minutes), 2h (hours), 1d (days)
minutes = self._parse_time_to_minutes(time_str)
```

## Testing

### Manual Testing

1. Create test YAML files in `examples/`:

```yaml
# examples/test_my_validator.yaml
id: 12345678-1234-1234-1234-123456789abc
name: "Test Detection"
# ... other required fields
```

2. Run the linter:

```bash
python linter.py examples/test_my_validator.yaml --verbose
```

3. Verify your validator runs and produces expected output

### Test Cases to Consider

- Valid input (should pass)
- Missing field (should error)
- Invalid format (should error)
- Edge cases (empty strings, None values, etc.)
- Cross-file scenarios (if applicable)

## Submitting Changes

### Before Submitting

1. Test your validator thoroughly
2. Update documentation:
   - Add to README.md under "Validation Checks"
   - Update IMPLEMENTATION_GUIDE.md if needed
3. Ensure code follows style guidelines
4. Add example files if needed

### Pull Request Process

1. Create a feature branch:

```bash
git checkout -b feature/my-new-validator
```

2. Make your changes and commit:

```bash
git add .
git commit -m "Add validator for XYZ"
```

3. Push to your fork:

```bash
git push origin feature/my-new-validator
```

4. Open a Pull Request with:
   - Clear description of what the validator does
   - Examples of what it catches
   - Test cases you've run

### Pull Request Template

```markdown
## Description
Brief description of the validator and what it checks.

## Motivation
Why is this validator needed?

## Examples
Examples of errors this validator catches.

## Testing
How you tested this validator.

## Checklist
- [ ] Code follows style guidelines
- [ ] Added docstrings
- [ ] Updated README.md
- [ ] Tested with valid and invalid inputs
- [ ] Added example files if needed
```

## Best Practices

### Performance

- Avoid expensive operations in validators
- Cache results if possible
- Don't load files multiple times

```python
# Good: Cache parsed data
if hasattr(self, '_cached_data'):
    return self._cached_data

# Bad: Parse file every time
data = load_yaml_file(file_path)
```

### Error Handling

Always handle exceptions gracefully:

```python
try:
    # Validation logic
    result = some_operation()
except Exception as e:
    errors.append(self.create_error(
        f"Validation failed: {str(e)}",
        field='field_name'
    ))
```

### Backwards Compatibility

When modifying existing validators:

- Don't change the validator name
- Don't change error message formats (add new ones instead)
- Maintain backwards compatibility with existing rules

## Questions?

If you have questions about contributing:

1. Check existing validators for examples
2. Review the documentation
3. Open an issue for discussion

Thank you for contributing!
