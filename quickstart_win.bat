@echo off

REM Sentinel Detection Linter Quick Start Script (Windows)

echo ================================================================
echo SENTINEL DETECTION LINTER - QUICK START
echo ================================================================
echo.

REM Prompt for setup mode
echo Choose setup mode:
echo   1) Full setup (with .NET SDK and KQL validation) - RECOMMENDED
echo   2) Basic setup (without .NET SDK, no KQL validation)
echo.
set /p SETUP_MODE="Enter choice [1-2]: "
echo.

REM Validate input and set defaults
if "%SETUP_MODE%"=="" set SETUP_MODE=1
if not "%SETUP_MODE%"=="1" if not "%SETUP_MODE%"=="2" (
    echo Invalid choice. Defaulting to Full setup.
    set SETUP_MODE=1
)

REM Set flags based on mode
if "%SETUP_MODE%"=="2" (
    set SKIP_DOTNET=true
    set NO_KQL_FLAG=--no-kql-validation
    echo Selected: Basic setup (no KQL validation^)
    echo NOTE: KQL syntax validation will be skipped in this mode.
) else (
    set SKIP_DOTNET=false
    set NO_KQL_FLAG=
    echo Selected: Full setup (with KQL validation^)
)
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed
    echo Please install Python 3.7 or higher from https://www.python.org/downloads/
    exit /b 1
)

REM Check if .NET is installed (only for full setup)
if "%SKIP_DOTNET%"=="false" (
    dotnet --version >nul 2>&1
    if errorlevel 1 (
        echo ERROR: .NET SDK is not installed
        echo Please install .NET SDK 6.0 or higher from https://dotnet.microsoft.com/download
        echo.
        echo Alternatively, run this script again and choose 'Basic setup' to skip KQL validation.
        exit /b 1
    )
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
if "%SKIP_DOTNET%"=="false" (
    dotnet --version
) else (
    echo .NET SDK: Skipped (basic mode^)
)
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

REM Run setup based on mode
echo Step 4: Running setup (inside virtual environment^)...
if "%SKIP_DOTNET%"=="false" (
    echo This will install dependencies and build the Kusto.Language DLL
    echo This may take 2-5 minutes...
    echo.
    python setup.py full-setup
) else (
    echo This will install Python dependencies only (no .NET components^)
    echo This may take 1-2 minutes...
    echo.
    python setup.py install-deps
)

echo.
echo ================================================================
echo SETUP COMPLETE - RUNNING DEMO
echo ================================================================
echo.

if "%SKIP_DOTNET%"=="true" (
    echo NOTE: Running in BASIC mode - KQL validation is disabled
    echo.
)

REM Demo 1: Validate valid detection
echo Demo 1: Validating a VALID detection file...
echo Command: python linter.py examples/valid_detection.yaml %NO_KQL_FLAG%
echo.
python linter.py examples/valid_detection.yaml %NO_KQL_FLAG%

echo.
echo ----------------------------------------------------------------
echo.

REM Demo 2: Validate invalid detection
echo Demo 2: Validating an INVALID detection file...
echo Command: python linter.py examples/invalid_detection.yaml %NO_KQL_FLAG%
echo.
python linter.py examples/invalid_detection.yaml %NO_KQL_FLAG%

echo.
echo ----------------------------------------------------------------
echo.

REM Demo 3: Validate directory
echo Demo 3: Validating entire examples directory...
echo Command: python linter.py --directory examples/ %NO_KQL_FLAG%
echo.
python linter.py --directory examples/ %NO_KQL_FLAG%

echo.
echo ================================================================
echo QUICK START COMPLETE
echo ================================================================
echo.
echo Next steps:
if "%SKIP_DOTNET%"=="false" (
    echo   1. Copy your detection YAML files to a directory
    echo   2. Run: python linter.py --directory your-detections/
    echo   3. Fix any validation errors (including KQL syntax^)
    echo   4. Integrate into your CI/CD pipeline
) else (
    echo   1. Copy your detection YAML files to a directory
    echo   2. Run: python linter.py --directory your-detections/ --no-kql-validation
    echo   3. Fix any validation errors (note: KQL syntax is NOT validated^)
    echo   4. Integrate into your CI/CD pipeline
    echo.
    echo   To enable KQL validation, install .NET SDK and run: python setup.py full-setup
)
echo.
echo For more information, see README.md and IMPLEMENTATION_GUIDE.md
echo.

pause
