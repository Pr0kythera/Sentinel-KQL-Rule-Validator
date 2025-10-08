#!/bin/bash

# Sentinel Detection Linter Quick Start Script
# This script sets up and demonstrates the linter

set -e

echo "================================================================"
echo "SENTINEL DETECTION LINTER - QUICK START"
echo "================================================================"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.7 or higher from https://www.python.org/downloads/"
    exit 1
fi

# Check if .NET is installed
if ! command -v dotnet &> /dev/null; then
    echo "ERROR: .NET SDK is not installed"
    echo "Please install .NET SDK 6.0 or higher from https://dotnet.microsoft.com/download"
    exit 1
fi

# Check if Git is installed
if ! command -v git &> /dev/null; then
    echo "ERROR: Git is not installed"
    echo "Please install Git from https://git-scm.com/downloads"
    exit 1
fi

echo "Step 1: Checking prerequisites..."
python3 --version
dotnet --version
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

# Run full setup
echo "Step 4: Running full setup (inside virtual environment)..."
echo "This will install dependencies and build the Kusto.Language DLL"
echo "This may take 2-5 minutes..."
echo ""
python setup.py full-setup

echo ""
echo "================================================================"
echo "SETUP COMPLETE - RUNNING DEMO"
echo "================================================================"
echo ""

# Demo 1: Validate valid detection
echo "Demo 1: Validating a VALID detection file..."
echo "Command: python linter.py examples/valid_detection.yaml"
echo ""
python linter.py examples/valid_detection.yaml

echo ""
echo "----------------------------------------------------------------"
echo ""

# Demo 2: Validate invalid detection
echo "Demo 2: Validating an INVALID detection file..."
echo "Command: python linter.py examples/invalid_detection.yaml"
echo ""
python linter.py examples/invalid_detection.yaml || true

echo ""
echo "----------------------------------------------------------------"
echo ""

# Demo 3: Validate directory
echo "Demo 3: Validating entire examples directory..."
echo "Command: python linter.py --directory examples/"
echo ""
python linter.py --directory examples/

echo ""
echo "================================================================"
echo "QUICK START COMPLETE"
echo "================================================================"
echo ""
echo "Next steps:"
echo "  1. Copy your detection YAML files to a directory"
echo "  2. Run: python linter.py --directory your-detections/"
echo "  3. Fix any validation errors"
echo "  4. Integrate into your CI/CD pipeline"
echo ""
echo "For more information, see README.md and IMPLEMENTATION_GUIDE.md"
echo ""
