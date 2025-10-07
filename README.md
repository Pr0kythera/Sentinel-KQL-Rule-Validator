# Sentinel Detection Linter

A comprehensive Python-based linter for validating Microsoft Sentinel Analytics Rules in YAML format before deployment. This tool performs extensive validation checks including GUID validation, schema validation, entity mapping verification, query timing validation, and full KQL syntax/semantic validation using Microsoft's official Kusto.Language library.

## Features

- **GUID Validation**: Validates GUID format and ensures uniqueness across all detection files
- **YAML Validation**: Checks YAML syntax, structure, and proper indentation
- **Data Type Validation**: Ensures all fields have correct data types (bool vs string, etc.)
- **Entity Mapping Validation**: Verifies entity mappings use strong identifiers per Microsoft documentation
- **Entity Column Validation**: Confirms entity mapping columns exist in KQL query output
- **Query Timing Validation**: Validates queryFrequency and queryPeriod constraints
- **KQL Query Validation**: Full syntax and semantic validation using Microsoft Kusto.Language library
- **Modular Architecture**: Easy to extend with new validation checks
- **Multiple Output Formats**: Console (human-readable) and JSON output

## Prerequisites

### Required Software

- **Python 3.7 or higher** (Python 3.10+ recommended)
- **.NET SDK 6.0 or higher** (for building Kusto.Language DLL)
  - Download from: https://dotnet.microsoft.com/download
- **Git** (for cloning Kusto.Language repository)

### Verify Prerequisites

Check that all required software is installed:

```bash
python --version        # Should show 3.7+
dotnet --version       # Should show 6.0+
git --version          # Should show git version
```

## Installation

### Step 1: Clone the Repository

```bash
git clone <your-repo-url>
cd sentinel-detection-linter
```

### Step 2: Run Full Setup

The setup script will:
1. Check prerequisites
2. Install Python dependencies
3. Clone and build the Kusto.Language DLL
4. Verify the installation

```bash
python setup.py full-setup
```

This process takes 2-5 minutes depending on your internet connection and machine speed.

### Alternative: Manual Setup

If you prefer to run steps individually:

```bash
# Install Python dependencies
python setup.py install-deps

# Build the Kusto.Language DLL
python setup.py build-dll

# Verify installation
python setup.py verify
```

## Project Structure

```
sentinel-detection-linter/
|
|-- linter.py                     # Main entry point
|-- setup.py                      # Setup and DLL build script
|-- requirements.txt              # Python dependencies
|-- README.md                     # This file
|
|-- libs/
|   |-- Kusto.Language.dll        # Microsoft KQL parser (built by setup)
|
|-- validators/
|   |-- base_validator.py         # Abstract base class
|   |-- guid_validator.py         # GUID validation
|   |-- schema_validator.py       # YAML schema validation
|   |-- entity_validator.py       # Entity mapping validation
|   |-- timing_validator.py       # Query timing validation
|   |-- kql_validator.py          # KQL syntax/semantic validation
|
|-- utils/
|   |-- yaml_loader.py            # Safe YAML loading
|   |-- file_scanner.py           # Directory scanning
|
|-- config/
|   |-- schema_definition.py      # Expected schema structure
|   |-- entity_identifiers.py     # Strong identifier mappings
|
|-- examples/
    |-- valid_rule.yaml            # Example valid detection
    |-- invalid_rules/             # Example invalid detections
```

## Usage

### Validate a Single File

```bash
python linter.py detection.yaml
```

### Validate All Files in a Directory

```bash
python linter.py --directory ./detections/
```

### Show Verbose Output (Including Warnings)

```bash
python linter.py detection.yaml --verbose
```

### Output as JSON

```bash
python linter.py detection.yaml --output json
```

### Disable KQL Validation

If .NET is not available or you want faster validation without KQL checking:

```bash
python linter.py detection.yaml --no-kql-validation
```

### Use Custom Schema

Provide your own schema definition for KQL semantic validation:

```bash
python linter.py detection.yaml --schema custom_schema.json
```

## Validation Checks

### 1. GUID Format Validation

Validates that the `id` field contains a valid GUID in the format:
`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

**Example Error:**
```
[ERROR] GUID Validator: Field 'id' contains invalid GUID format: 'not-a-guid'
```

### 2. GUID Uniqueness Validation

Ensures the GUID is unique across all YAML files in the same directory.

**Example Error:**
```
[ERROR] GUID Validator: GUID 'c6a213e4-f321-4f78-b12a-3e0e7d56e29a' is not unique. 
        Also found in: detection2.yaml, detection3.yaml
```

### 3. YAML Format Validation

Checks for proper YAML syntax and indentation.

**Example Error:**
```
[ERROR] YAML Parser: YAML parsing error at line 15, column 3: 
        mapping values are not allowed here
```

### 4. Data Type Validation

Ensures fields have correct data types. Common issue: boolean values as strings.

**Example Error:**
```
[ERROR] Schema Validator: Field 'enabled' has incorrect type. Expected bool, got str.
        Use enabled: true instead of enabled: 'true'
```

### 5. Entity Strong Identifier Validation

Validates entity mappings use strong identifiers per Microsoft documentation.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/entities-reference

**Example Warning:**
```
[WARN] Entity Validator: Entity type 'Account' is using identifier 'Name' which may not be
       a strong identifier. Recommended strong identifiers: FullName, Sid, AadUserId, ObjectGuid
```

### 6. Entity Column Validation

Confirms that entity mapping columnNames exist in the KQL query output.

**Example Error:**
```
[ERROR] KQL Validator: Entity mapping for 'Account' references column 'NonExistentColumn' 
        which is not present in query output. Available columns: Computer, Account, EventID
```

### 7. Query Timing Validation

Validates queryFrequency and queryPeriod constraints:
- queryPeriod cannot exceed 14 days
- queryFrequency must be less than or equal to queryPeriod

**Example Error:**
```
[ERROR] Timing Validator: queryFrequency '2h' (120 minutes) cannot exceed 
        queryPeriod '1h' (60 minutes)
```

### 8. KQL Query Validation

Full syntax and semantic validation using Microsoft's official parser.

**Syntax Error Example:**
```
[ERROR] KQL Validator: KQL syntax error: The name 'sorty' does not refer to any known 
        column, table, variable or function. Issue at position 45: 'sorty'
```

**Semantic Error Example:**
```
[ERROR] KQL Validator: KQL semantic error: The name 'NonExistentTable' does not refer 
        to any known table
```

## Output Formats

### Console Output (Default)

```
======================================================================
SENTINEL DETECTION LINTER - VALIDATION RESULTS
======================================================================

[PASS] valid_detection.yaml

[FAIL] invalid_detection.yaml
  [ERROR] GUID Validator: Field 'id' contains invalid GUID format: 'invalid-guid'
  [ERROR] KQL Validator: KQL syntax error: Expected operator

======================================================================
Summary: 1/2 files passed
         2 errors, 0 warnings
======================================================================
```

### JSON Output

```json
{
  "timestamp": "2025-10-07T12:00:00Z",
  "summary": {
    "total_files": 2,
    "passed": 1,
    "failed": 1,
    "total_errors": 2,
    "total_warnings": 0
  },
  "results": [
    {
      "file": "valid_detection.yaml",
      "status": "passed",
      "errors": [],
      "warnings": []
    },
    {
      "file": "invalid_detection.yaml",
      "status": "failed",
      "errors": [
        {
          "validator": "GUID Validator",
          "severity": "error",
          "message": "Field 'id' contains invalid GUID format: 'invalid-guid'",
          "field": "id"
        }
      ],
      "warnings": []
    }
  ]
}
```

## Custom Schema Configuration

You can provide a custom schema for KQL semantic validation. Create a JSON file:

```json
{
  "database": "MySecurityDB",
  "tables": {
    "CustomSecurityEvents": {
      "columns": {
        "TimeGenerated": "datetime",
        "DeviceName": "string",
        "UserName": "string",
        "EventType": "string",
        "Severity": "int"
      }
    }
  }
}
```

Then use it:

```bash
python linter.py detection.yaml --schema my_schema.json
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Validate Detections

on:
  pull_request:
    paths:
      - 'detections/**/*.yaml'

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Setup .NET
        uses: actions/setup-dotnet@v3
        with:
          dotnet-version: '7.0'
      
      - name: Install and Setup Linter
        run: |
          python setup.py full-setup
      
      - name: Validate Detections
        run: |
          python linter.py --directory ./detections/ --output json > results.json
      
      - name: Upload Results
        if: failure()
        uses: actions/upload-artifact@v3
        with:
          name: validation-results
          path: results.json
```

### Azure DevOps Pipeline Example

```yaml
trigger:
  branches:
    include:
      - main
  paths:
    include:
      - detections/**/*.yaml

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'
  displayName: 'Setup Python'

- task: UseDotNet@2
  inputs:
    version: '7.x'
  displayName: 'Setup .NET'

- script: |
    python setup.py full-setup
  displayName: 'Install Linter'

- script: |
    python linter.py --directory ./detections/ --output json
  displayName: 'Validate Detections'
```

## Extending the Linter

### Adding a New Validator

1. Create a new validator class in `validators/`:

```python
from .base_validator import BaseValidator
from pathlib import Path
from typing import List, Dict

class MyCustomValidator(BaseValidator):
    @property
    def validator_name(self) -> str:
        return "My Custom Validator"
    
    def validate(self, rule_data: dict, file_path: Path, 
                 all_files: List[Path] = None) -> List[Dict]:
        errors = []
        
        # Your validation logic here
        if 'some_field' not in rule_data:
            errors.append(self.create_error(
                "Missing required field 'some_field'",
                field='some_field'
            ))
        
        return errors
```

2. Register it in `linter.py`:

```python
from validators.my_custom_validator import MyCustomValidator

# In SentinelLinter.__init__:
self.validators.append(MyCustomValidator())
```

## Troubleshooting

### Issue: "Kusto.Language.dll not found"

**Solution:** Run the build command:
```bash
python setup.py build-dll
```

### Issue: "Python.NET not installed"

**Solution:** Install pythonnet:
```bash
pip install pythonnet
```

### Issue: ".NET SDK not found"

**Solution:** Install .NET SDK 6.0 or higher from:
https://dotnet.microsoft.com/download

### Issue: "Failed to initialize pythonnet"

**Solution:** This can happen on some Linux systems. Try:
```bash
pip uninstall pythonnet
pip install pythonnet==3.0.5
```

### Issue: Linter is slow

**Solution:** For faster validation during development:
```bash
python linter.py detection.yaml --no-kql-validation
```

This disables KQL validation and only runs structural checks.

### Issue: False positives in KQL validation

**Solution:** Provide a custom schema that matches your environment:
```bash
python linter.py detection.yaml --schema your_schema.json
```

## Performance

Typical performance on a modern laptop:

- Single file validation: 200-500ms
- Directory with 50 files: 10-25 seconds
- Directory with 500 files: 2-4 minutes

Performance optimization tips:
- Use `--no-kql-validation` for quick structural checks
- Run in parallel for large detection repositories
- Cache the DLL loading by keeping the linter process running

## Security Considerations

This linter:
- Uses `yaml.safe_load()` to prevent code execution
- Validates file paths to prevent directory traversal
- Does not make external network calls during validation
- Only uses well-known, auditable dependencies

## Contributing

Contributions are welcome! To add new validators:

1. Create a new validator class extending `BaseValidator`
2. Implement the `validate()` method
3. Add tests for your validator
4. Update this README with documentation
5. Submit a pull request

## License

[Your License Here]

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Contact: [Your Contact Information]

## Acknowledgments

- Microsoft for the Kusto.Language library
- Python.NET team for the CLR bridge
- The Sentinel community for feedback and testing

## Version History

### v1.0.0 (2025-10-07)
- Initial release
- Full validation suite
- Support for Microsoft Kusto.Language integration
- Console and JSON output formats
- CI/CD examples
