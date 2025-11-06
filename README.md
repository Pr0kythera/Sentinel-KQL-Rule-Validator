# Sentinel Detection Linter

A comprehensive Python-based linter for validating Microsoft Sentinel Analytics Rules in YAML format before deployment. This tool performs extensive validation checks including GUID validation, schema validation, Microsoft Sentinel constraints, ASIM field naming, entity mapping verification, query timing validation, and full KQL syntax/semantic validation using Microsoft's official Kusto.Language library.

## Features

- **GUID Validation**: Validates GUID format and ensures uniqueness across all detection files
- **YAML Validation**: Checks YAML syntax, structure, and proper indentation
- **Data Type Validation**: Ensures all fields have correct data types (bool vs string, etc.)
- **Sentinel Constraints Validation**: Validates all Microsoft Sentinel field requirements (kind, severity, tactics, techniques, limits, etc.)
- **ASIM Field Naming**: Warns when entity mappings don't follow ASIM normalized field naming conventions
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

### Step 2: Create and Activate Virtual Environment (Recommended)

Using a virtual environment isolates the linter's dependencies from your system Python and prevents conflicts.

**Linux/Mac:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Your prompt should now show (venv) prefix
```

**Windows:**
```batch
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate.bat

# Your prompt should now show (venv) prefix
```

**Note:** You'll need to activate the virtual environment each time you open a new terminal session before running the linter.

**Having trouble with virtual environments?** See the comprehensive [Virtual Environment Guide](VIRTUAL_ENVIRONMENT_GUIDE.md) for detailed instructions and troubleshooting.

### Step 3: Run Full Setup

The setup script will:
1. Check prerequisites
2. Install Python dependencies
3. Clone and build the Kusto.Language DLL
4. Verify the installation

```bash
python setup.py full-setup
```

This process takes 2-5 minutes depending on your internet connection and machine speed.

### Alternative: Quick Start Script

For a fully automated setup including venv creation:

**Linux/Mac:**
```bash
chmod +x quickstart.sh
./quickstart.sh
```

**Windows:**
```batch
quickstart.bat
```

**For Non DOTNET installation**

If you cannot install .net to use (--no-kql-validation) on the device after activating your ven Simply run the following to install the dependencies
```bash
pip install -r requirements.txt

```

### Step 4: Verify Installation

```bash
python linter.py examples/valid_detection.yaml
```

Expected output: `[PASS] valid_detection.yaml`

### Deactivating Virtual Environment

When you're done using the linter:

```bash
deactivate
```

## Project Structure

```
sentinel-detection-linter/
|
|-- linter.py                              # Main entry point
|-- setup.py                               # Setup and DLL build script
|-- requirements.txt                       # Python dependencies
|-- README.md                              # This file
|
|-- libs/
|   |-- Kusto.Language.dll                 # Microsoft KQL parser (built by setup)
|
|-- validators/
|   |-- base_validator.py                  # Abstract base class
|   |-- guid_validator.py                  # GUID validation
|   |-- schema_validator.py                # YAML schema validation
|   |-- sentinel_constraints_validator.py  # Microsoft Sentinel constraints
|   |-- entity_validator.py                # Entity mapping validation
|   |-- asim_field_validator.py            # ASIM field naming validation
|   |-- timing_validator.py                # Query timing validation
|   |-- kql_validator.py                   # KQL syntax/semantic validation
|
|-- utils/
|   |-- yaml_loader.py                     # Safe YAML loading
|   |-- file_scanner.py                    # Directory scanning
|
|-- config/
|   |-- schema_definition.py               # Expected schema structure
|   |-- entity_identifiers.py              # Strong identifier mappings
|   |-- asim_field_names.py                # ASIM normalized field names
|
|-- examples/
    |-- valid_detection.yaml                # Example valid detection
    |-- detection_with_asim_warnings.yaml   # ASIM field naming examples
    |-- detection_with_constraint_errors.yaml  # Constraint violation examples
    |-- detection_with_valid_constraints.yaml  # Valid constraints example
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

The linter performs validations in the following order:

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

### 5. Microsoft Sentinel Constraints Validation

Validates all Microsoft Sentinel Analytics Rule requirements per official documentation.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/sentinel-analytic-rules-creation

**Validated Constraints:**

#### Field Values (Enums)
- **kind**: Must be "Scheduled" or "NRT"
- **severity**: Must be "Informational", "Low", "Medium", or "High"
- **triggerOperator**: Must be "GreaterThan", "LessThan", or "Equal"
- **eventGroupingSettings.aggregationKind**: Must be "SingleAlert" or "AlertPerResult"

#### Numeric Ranges
- **triggerThreshold**: Must be integer between 0 and 10,000

#### Length Limits
- **name**: Maximum 50 characters, cannot end with period
- **description**: Maximum 255 characters
- **query**: Maximum 10,000 characters
- **entityMappings**: Maximum 10 mappings per rule
- **fieldMappings**: Maximum 3 per entity
- **customDetails**: Maximum 20 key/value pairs
- **alertDetailsOverride**: Maximum 3 parameters, specific character limits

#### Format Requirements
- **version**: Must follow semantic versioning (e.g., "1.0.0")

#### MITRE ATT&CK Validation
- **tactics**: Must be valid MITRE ATT&CK v13 tactics (no spaces)
  - Valid: InitialAccess, Execution, Persistence, PrivilegeEscalation, DefenseEvasion, CredentialAccess, Discovery, LateralMovement, Collection, CommandAndControl, Exfiltration, Impact, Reconnaissance, ResourceDevelopment
- **relevantTechniques**: Must follow format T1000-T1999 or T1000-T1999.001-999
  - Valid: "T1078", "T1078.001", "T1110"
  - Invalid: "T999", "T2000", "1078", "Initial Access"

**Example Errors:**
```
[ERROR] Sentinel Constraints Validator: Field 'kind' has invalid value 'Custom'. 
        Must be one of: 'Scheduled', 'NRT'

[ERROR] Sentinel Constraints Validator: Field 'severity' has invalid value 'Critical'. 
        Must be one of: 'Informational', 'Low', 'Medium', 'High'

[ERROR] Sentinel Constraints Validator: Tactic 'Initial Access' contains spaces. 
        MITRE ATT&CK tactics must not contain spaces. Use 'InitialAccess' instead

[ERROR] Sentinel Constraints Validator: Technique 'T999' has invalid format. 
        Must be 'T####' (e.g., T1078) or 'T####.###' (e.g., T1078.001) 
        where #### is in range 1000-1999

[ERROR] Sentinel Constraints Validator: Field 'name' exceeds maximum length of 50 characters. 
        Current length: 75 characters

[ERROR] Sentinel Constraints Validator: Field 'entityMappings' exceeds maximum of 10 mappings. 
        Current count: 11 mappings
```

### 6. Entity Strong Identifier Validation

Validates entity mappings use strong identifiers per Microsoft documentation.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/entities-reference

**Example Warning:**
```
[WARN] Entity Validator: Entity type 'Account' is using identifier 'Name' which may not be
       a strong identifier. Recommended strong identifiers: FullName, Sid, AadUserId, ObjectGuid
```

### 7. ASIM Field Naming Validation

Warns when entity mapping `columnName` values don't follow ASIM (Advanced Security Information Model) normalized field naming conventions.

Reference: https://learn.microsoft.com/en-us/azure/sentinel/normalization-common-fields

**ASIM Field Patterns:**
- User/Account: ActorUsername, TargetUsername, ActorUserId, SrcUsername
- Host/Device: SrcHostname, DstHostname, DvcIpAddr, SrcIpAddr
- Process: ActingProcessName, TargetProcessId, ActingProcessCommandLine
- File: TargetFileName, SrcFilePath, TargetFileSHA256

**Example Warning:**
```
[WARN] ASIM Field Validator: Entity mapping for 'Account' uses columnName 'Account' 
       which does not follow ASIM normalized field naming conventions. 
       For 'Account' entities, ASIM recommends field names like: ActorUsername, 
       TargetUsername, ActorUserId, SrcUsername. Using ASIM-normalized field names 
       improves query consistency and cross-source correlation.
```

### 8. Entity Column Validation

Confirms that entity mapping columnNames exist in the KQL query output.

**Example Error:**
```
[ERROR] KQL Validator: Entity mapping for 'Account' references column 'NonExistentColumn' 
        which is not present in query output. Available columns: Computer, Account, EventID
```

### 9. Query Timing Validation

Validates queryFrequency and queryPeriod constraints:
- queryPeriod cannot exceed 14 days
- queryFrequency must be less than or equal to queryPeriod

**Example Error:**
```
[ERROR] Timing Validator: queryFrequency '2h' (120 minutes) cannot exceed 
        queryPeriod '1h' (60 minutes)
```

### 10. KQL Query Validation

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
  [ERROR] Sentinel Constraints Validator: Field 'kind' has invalid value 'Custom'
  [ERROR] KQL Validator: KQL syntax error: Expected operator

======================================================================
Summary: 1/2 files passed
         3 errors, 0 warnings
======================================================================
```

### JSON Output

```json
{
  "timestamp": "2025-10-09T12:00:00Z",
  "summary": {
    "total_files": 2,
    "passed": 1,
    "failed": 1,
    "total_errors": 3,
    "total_warnings": 1
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
        },
        {
          "validator": "Sentinel Constraints Validator",
          "severity": "error",
          "message": "Field 'kind' has invalid value 'Custom'. Must be one of: 'Scheduled', 'NRT'",
          "field": "kind"
        }
      ],
      "warnings": [
        {
          "validator": "ASIM Field Validator",
          "severity": "warning",
          "message": "Entity mapping for 'Account' uses columnName 'Account'...",
          "field": "entityMappings[0].fieldMappings[0].columnName"
        }
      ]
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

### Issue: ASIM warnings for valid custom fields

**Solution:** ASIM field naming is advisory (warnings, not errors). You can acknowledge these warnings for custom environments. To see only errors:
```bash
python linter.py detection.yaml  # (without --verbose, warnings are hidden)
```

### Issue: Constraint errors for valid rules

**Solution:** Ensure your rules follow Microsoft Sentinel requirements:
- Use "Scheduled" or "NRT" for `kind`
- Use valid severity levels
- Follow MITRE ATT&CK v13 naming (no spaces in tactics)
- Keep names under 50 characters
- See [Sentinel Constraints Guide](SENTINEL_CONSTRAINTS_VALIDATION_GUIDE.md) for details

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

MIT License - See LICENSE file for details

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Review the documentation guides below

## Documentation

### User Guides
- **README.md** (this file) - Overview and user guide
- **INSTALLATION_SUMMARY.md** - Quick reference for installation
- **VIRTUAL_ENVIRONMENT_GUIDE.md** - Complete guide to using Python virtual environments

### Validation Guides
- **SENTINEL_CONSTRAINTS_VALIDATION_GUIDE.md** - Microsoft Sentinel constraints validation
- **ASIM_FIELD_VALIDATION_GUIDE.md** - ASIM field naming conventions

### Technical Documentation
- **IMPLEMENTATION_GUIDE.md** - Detailed step-by-step implementation instructions
- **CROSS_PLATFORM_NOTES.md** - How DLLs work across Windows, macOS, and Linux
- **MACOS_SETUP_GUIDE.md** - macOS-specific setup and troubleshooting
- **CONTRIBUTING.md** - Guide for adding custom validators
- **DEPLOYMENT_GUIDE.md** - Instructions for deploying to your organization

### Implementation Summaries
- **ASIM_VALIDATOR_IMPLEMENTATION_SUMMARY.md** - ASIM validator technical details
- **SENTINEL_CONSTRAINTS_IMPLEMENTATION_SUMMARY.md** - Constraints validator technical details

## Acknowledgments

- Microsoft for the Kusto.Language library and Sentinel documentation
- Python.NET team for the CLR bridge
- The Sentinel community for feedback and testing
- MITRE for the ATT&CK framework

## Version History

### v1.1.0 (2025-10-09)
- **Added**: Sentinel Constraints Validator - Validates all Microsoft Sentinel requirements
  - Field value constraints (kind, severity, triggerOperator)
  - Numeric range validation (triggerThreshold)
  - Length limits (name, description, query, entity mappings, custom details)
  - Format validation (version semantic versioning)
  - MITRE ATT&CK v13 tactics and techniques validation
- **Added**: ASIM Field Validator - Validates entity mappings follow ASIM naming conventions
  - 500+ ASIM normalized field names
  - Entity-specific recommendations
  - Cross-source correlation improvements
- **Updated**: Schema validator to include new required fields (tactics, relevantTechniques, version)
- **Updated**: Configuration with ASIM field definitions
- **Added**: Comprehensive validation guides and examples

### v1.0.0 (2025-10-07)
- Initial release
- Full validation suite
- Support for Microsoft Kusto.Language integration
- Console and JSON output formats
- CI/CD examples
