# Sentinel Detection Linter - Installation Summary

Quick reference guide for installing and deploying the Sentinel Detection Linter.

## Prerequisites Checklist

- [ ] Python 3.7+ installed (3.10+ recommended)
- [ ] .NET SDK 6.0+ installed
- [ ] Git installed
- [ ] 500MB free disk space (for build artifacts)
- [ ] Internet connection (for initial setup)

## Installation Methods

### Method 1: Quick Start (Recommended)

**Linux/Mac:**
```bash
git clone <repo-url>
cd sentinel-detection-linter
chmod +x quickstart.sh
./quickstart.sh
```

**Windows:**
```batch
git clone <repo-url>
cd sentinel-detection-linter
quickstart.bat
```

### Method 2: Manual Step-by-Step

```bash
# 1. Clone repository
git clone <repo-url>
cd sentinel-detection-linter

# 2. Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Run setup
python setup.py full-setup

# 4. Verify
python linter.py examples/valid_detection.yaml
```

### Method 3: Individual Steps

```bash
# Check prerequisites
python setup.py check

# Install Python dependencies only
python setup.py install-deps

# Build Kusto.Language DLL only
python setup.py build-dll

# Verify installation
python setup.py verify
```

## File Structure After Installation

```
sentinel-detection-linter/
|-- linter.py                 # Main script - RUN THIS
|-- setup.py                  # Setup script
|-- requirements.txt
|-- README.md
|
|-- libs/
|   |-- Kusto.Language.dll    # Built during setup (~3MB)
|
|-- validators/               # Validation modules
|-- utils/                    # Helper utilities
|-- config/                   # Configuration
|-- examples/                 # Test files
```

## Basic Usage

### Validate Single File

```bash
python linter.py detection.yaml
```

### Validate Directory

```bash
python linter.py --directory ./detections/
```

### Get Verbose Output

```bash
python linter.py detection.yaml --verbose
```

### Output as JSON

```bash
python linter.py detection.yaml --output json
```

## Platform-Specific Notes

### Windows

- Use backslashes in paths: `python linter.py detections\rule.yaml`
- Ensure Python is in PATH
- May need to run as Administrator for some .NET operations
- Use `py` instead of `python` if multiple Python versions installed

### Linux

- May need `python3` instead of `python`
- Ensure .NET Core runtime is installed: `sudo apt-get install dotnet-runtime-7.0`
- Make scripts executable: `chmod +x quickstart.sh`

### macOS

- Use `python3` instead of `python`
- May need to install .NET SDK from Microsoft website
- Use Homebrew for easy installation: `brew install dotnet`

## Troubleshooting Quick Reference

| Issue | Solution |
|-------|----------|
| "DLL not found" | Run `python setup.py build-dll` |
| "pythonnet not installed" | Run `pip install pythonnet` |
| ".NET SDK not found" | Install from https://dotnet.microsoft.com/download |
| "Permission denied" | Run with appropriate permissions or use virtual environment |
| Build fails | Check .NET SDK version with `dotnet --version` |
| Slow performance | Use `--no-kql-validation` for quick checks |

## Configuration Options

### Disable KQL Validation

When .NET is not available or for faster validation:

```bash
python linter.py detection.yaml --no-kql-validation
```

### Custom Schema

For environment-specific table/column validation:

```bash
python linter.py detection.yaml --schema custom_schema.json
```

### Output Formats

**Console (default):**
```bash
python linter.py detection.yaml
```

**JSON:**
```bash
python linter.py detection.yaml --output json > results.json
```

## CI/CD Quick Setup

### GitHub Actions

Add to `.github/workflows/validate.yml`:

```yaml
- uses: actions/setup-python@v4
  with:
    python-version: '3.11'
- uses: actions/setup-dotnet@v3
  with:
    dotnet-version: '7.0'
- run: python setup.py full-setup
- run: python linter.py --directory ./detections/
```

### Azure DevOps

Add to `azure-pipelines.yml`:

```yaml
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'
- task: UseDotNet@2
  inputs:
    version: '7.x'
- script: python setup.py full-setup
- script: python linter.py --directory ./detections/
```

## Validation Checks Summary

The linter performs these checks:

1. GUID format and uniqueness
2. YAML syntax and structure
3. Data type validation
4. Entity mapping validation
5. Strong identifier usage
6. Query timing constraints
7. KQL syntax validation
8. KQL semantic validation

## Exit Codes

- `0`: All validations passed
- `1`: One or more validations failed

Use in scripts:
```bash
if python linter.py detection.yaml; then
    echo "Validation passed"
else
    echo "Validation failed"
    exit 1
fi
```

## Performance Expectations

| Operation | Time |
|-----------|------|
| Single file (with KQL) | 200-500ms |
| Single file (no KQL) | 50-100ms |
| 50 files | 10-25 seconds |
| 500 files | 2-4 minutes |
| Initial DLL load | 500ms (one-time) |

## Updating

To update to a new version:

```bash
git pull origin main
python setup.py install-deps
python setup.py build-dll
```

## Uninstalling

To remove the linter:

```bash
# Deactivate virtual environment
deactivate

# Remove directory
cd ..
rm -rf sentinel-detection-linter
```

## Getting Help

1. Check README.md for detailed documentation
2. Check IMPLEMENTATION_GUIDE.md for step-by-step instructions
3. Review examples/ directory for sample files
4. Check CONTRIBUTING.md if extending the linter

## Support Resources

- GitHub Issues: [Your repo]/issues
- Documentation: See README.md
- Examples: See examples/ directory

## Next Steps After Installation

1. **Test with examples:**
   ```bash
   python linter.py --directory examples/
   ```

2. **Validate your detections:**
   ```bash
   python linter.py --directory /path/to/your/detections/
   ```

3. **Fix any errors** reported by the linter

4. **Integrate into CI/CD** (see README.md for examples)

5. **Set up pre-commit hook** (see examples/pre-commit-hook.sh)

6. **Customize if needed:**
   - Add custom tables to `config/schema_definition.py`
   - Create custom schema JSON files
   - Add organization-specific validators

## Minimum Working Example

After installation, this should work:

```bash
# Create a simple detection
cat > test.yaml << 'EOF'
id: 12345678-1234-1234-1234-123456789abc
name: "Test Detection"
displayName: "Test Detection Display"
kind: "Scheduled"
description: "Test"
severity: "Medium"
enabled: true
queryFrequency: "5m"
queryPeriod: "5m"
triggerOperator: "GreaterThan"
triggerThreshold: 0
query: "SecurityEvent | take 10"
EOF

# Validate it
python linter.py test.yaml

# Should show: [PASS] test.yaml
```

## Quick Commands Reference

```bash
# Full setup
python setup.py full-setup

# Validate single file
python linter.py file.yaml

# Validate directory
python linter.py -d ./detections/

# Verbose output
python linter.py file.yaml -v

# JSON output
python linter.py file.yaml -o json

# Without KQL validation
python linter.py file.yaml --no-kql-validation

# With custom schema
python linter.py file.yaml --schema schema.json

# Help
python linter.py --help
```
