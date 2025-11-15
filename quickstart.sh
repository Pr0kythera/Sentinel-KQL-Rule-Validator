#!/bin/bash

# Sentinel Detection Linter Quick Start Script
# This script sets up and demonstrates the linter

set -e

echo "================================================================"
echo "SENTINEL DETECTION LINTER - QUICK START"
echo "================================================================"
echo ""

# Prompt for setup mode
echo "Choose setup mode:"
echo "  1) Full setup (with .NET SDK and KQL validation) - RECOMMENDED"
echo "  2) Basic setup (without .NET SDK, no KQL validation)"
echo ""
read -p "Enter choice [1-2]: " SETUP_MODE
echo ""

# Validate input
if [[ "$SETUP_MODE" != "1" && "$SETUP_MODE" != "2" ]]; then
    echo "Invalid choice. Defaulting to Full setup."
    SETUP_MODE=1
fi

# Set flags based on mode
if [ "$SETUP_MODE" = "2" ]; then
    SKIP_DOTNET=true
    NO_KQL_FLAG="--no-kql-validation"
    echo "Selected: Basic setup (no KQL validation)"
    echo "NOTE: KQL syntax validation will be skipped in this mode."
else
    SKIP_DOTNET=false
    NO_KQL_FLAG=""
    echo "Selected: Full setup (with KQL validation)"
fi
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.7 or higher from https://www.python.org/downloads/"
    exit 1
fi

# Check if .NET is installed (only for full setup)
if [ "$SKIP_DOTNET" = false ]; then
    if ! command -v dotnet &> /dev/null; then
        echo "ERROR: .NET SDK is not installed"
        echo "Please install .NET SDK 6.0 or higher from https://dotnet.microsoft.com/download"
        echo ""
        echo "Alternatively, run this script again and choose 'Basic setup' to skip KQL validation."
        exit 1
    fi
fi

# Check if Git is installed
if ! command -v git &> /dev/null; then
    echo "ERROR: Git is not installed"
    echo "Please install Git from https://git-scm.com/downloads"
    exit 1
fi

echo "Step 1: Checking prerequisites..."
python3 --version
if [ "$SKIP_DOTNET" = false ]; then
    dotnet --version
else
    echo ".NET SDK: Skipped (basic mode)"
fi
git --version
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Step 2: Creating Python virtual environment..."
    echo "This isolates dependencies from your system Python."
    python3 -m venv venv
    echo "  [OK] Virtual environment created"
    echo ""
fi

# Activate virtual environment
echo "Step 3: Activating virtual environment..."
source venv/bin/activate
echo "  [OK] Virtual environment activated"
echo "  Python: $(which python)"
echo ""

# Run setup based on mode
echo "Step 4: Running setup (inside virtual environment)..."
if [ "$SKIP_DOTNET" = false ]; then
    echo "This will install dependencies and build the Kusto.Language DLL"
    echo "This may take 2-5 minutes..."
    echo ""
    python setup.py full-setup
else
    echo "This will install Python dependencies only (no .NET components)"
    echo "This may take 1-2 minutes..."
    echo ""
    python setup.py install-deps
fi

echo ""
echo "================================================================"
echo "SETUP COMPLETE - RUNNING DEMO"
echo "================================================================"
echo ""

if [ "$SKIP_DOTNET" = true ]; then
    echo "NOTE: Running in BASIC mode - KQL validation is disabled"
    echo ""
fi

# Demo 1: Validate valid detection
echo "Demo 1: Validating a VALID detection file..."
echo "Command: python linter.py examples/valid_detection.yaml $NO_KQL_FLAG"
echo ""
python linter.py examples/valid_detection.yaml $NO_KQL_FLAG

echo ""
echo "----------------------------------------------------------------"
echo ""

# Demo 2: Validate invalid detection
echo "Demo 2: Validating an INVALID detection file..."
echo "Command: python linter.py examples/invalid_detection.yaml $NO_KQL_FLAG"
echo ""
python linter.py examples/invalid_detection.yaml $NO_KQL_FLAG || true

echo ""
echo "----------------------------------------------------------------"
echo ""

# Demo 3: Validate directory
echo "Demo 3: Validating entire examples directory..."
echo "Command: python linter.py --directory examples/ $NO_KQL_FLAG"
echo ""
python linter.py --directory examples/ $NO_KQL_FLAG

echo ""
echo "================================================================"
echo "QUICK START COMPLETE"
echo "================================================================"
echo ""
echo "Next steps:"
if [ "$SKIP_DOTNET" = false ]; then
    echo "  1. Copy your detection YAML files to a directory"
    echo "  2. Run: python linter.py --directory your-detections/"
    echo "  3. Fix any validation errors (including KQL syntax)"
    echo "  4. Integrate into your CI/CD pipeline"
else
    echo "  1. Copy your detection YAML files to a directory"
    echo "  2. Run: python linter.py --directory your-detections/ --no-kql-validation"
    echo "  3. Fix any validation errors (note: KQL syntax is NOT validated)"
    echo "  4. Integrate into your CI/CD pipeline"
    echo ""
    echo "  To enable KQL validation, install .NET SDK and run: python setup.py full-setup"
fi
echo ""
echo "For more information, see README.md and IMPLEMENTATION_GUIDE.md"
echo ""
