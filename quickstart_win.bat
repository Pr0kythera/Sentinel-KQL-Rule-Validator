@echo off

REM Sentinel Detection Linter Quick Start Script (Windows)

echo ================================================================
echo SENTINEL DETECTION LINTER - QUICK START
echo ================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed
    echo Please install Python 3.7 or higher from https://www.python.org/downloads/
    exit /b 1
)

REM Check if .NET is installed
dotnet --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: .NET SDK is not installed
    echo Please install .NET SDK 6.0 or higher from https://dotnet.microsoft.com/download
    exit /b 1
)

REM Check if Git is installed
git --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed
    echo Please install Git from https://git-scm.com/downloads
    exit /b 1
)

echo Step 1: Checking prerequisites...
python --version
dotnet --version
git --version
echo.

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Step 2: Creating Python virtual environment...
    echo This isolates dependencies from your system Python.
    python -m venv venv
    echo   [OK] Virtual environment created
    echo.
)

REM Activate virtual environment
echo Step 3: Activating virtual environment...
call venv\Scripts\activate.bat
echo   [OK] Virtual environment activated
echo   Python: %VIRTUAL_ENV%\Scripts\python.exe
echo.

REM Run full setup
echo Step 4: Running full setup (inside virtual environment)...
echo This will install dependencies and build the Kusto.Language DLL
echo This may take 2-5 minutes...
echo.
python setup.py full-setup

echo.
echo ================================================================
echo SETUP COMPLETE - RUNNING DEMO
echo ================================================================
echo.

REM Demo 1: Validate valid detection
echo Demo 1: Validating a VALID detection file...
echo Command: python linter.py examples/valid_detection.yaml
echo.
python linter.py examples/valid_detection.yaml

echo.
echo ----------------------------------------------------------------
echo.

REM Demo 2: Validate invalid detection
echo Demo 2: Validating an INVALID detection file...
echo Command: python linter.py examples/invalid_detection.yaml
echo.
python linter.py examples/invalid_detection.yaml

echo.
echo ----------------------------------------------------------------
echo.

REM Demo 3: Validate directory
echo Demo 3: Validating entire examples directory...
echo Command: python linter.py --directory examples/
echo.
python linter.py --directory examples/

echo.
echo ================================================================
echo QUICK START COMPLETE
echo ================================================================
echo.
echo Next steps:
echo   1. Copy your detection YAML files to a directory
echo   2. Run: python linter.py --directory your-detections/
echo   3. Fix any validation errors
echo   4. Integrate into your CI/CD pipeline
echo.
echo For more information, see README.md and IMPLEMENTATION_GUIDE.md
echo.

pause
