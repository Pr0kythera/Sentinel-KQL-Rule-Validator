#!/usr/bin/env python3
"""
Setup script for Sentinel Detection Linter
Handles building the Kusto.Language DLL
"""

import sys
import subprocess
import shutil
from pathlib import Path
import argparse


class SetupManager:
    """Manages setup and DLL building"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.libs_dir = self.project_root / "libs"
        self.temp_dir = self.project_root / "temp_kusto"
    
    def check_prerequisites(self):
        """Check if required tools are installed"""
        print("Checking prerequisites...")
        
        # Check Python version
        if sys.version_info < (3, 7):
            print("ERROR: Python 3.7 or higher is required")
            return False
        print(f"  [OK] Python {sys.version_info.major}.{sys.version_info.minor}")
        
        # Check for git
        try:
            result = subprocess.run(['git', '--version'], 
                                  capture_output=True, text=True, check=True)
            print(f"  [OK] {result.stdout.strip()}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("  [ERROR] Git is not installed or not in PATH")
            return False
        
        # Check for dotnet
        try:
            result = subprocess.run(['dotnet', '--version'], 
                                  capture_output=True, text=True, check=True)
            version = result.stdout.strip()
            print(f"  [OK] .NET SDK {version}")
            
            # Check if version is 6.0 or higher
            major_version = int(version.split('.')[0])
            if major_version < 6:
                print(f"  [WARNING] .NET SDK 6.0 or higher recommended, found {version}")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("  [ERROR] .NET SDK is not installed or not in PATH")
            print("  Download from: https://dotnet.microsoft.com/download")
            return False
        
        print("\nAll prerequisites met!\n")
        return True
    
    def build_dll(self):
        """Clone and build Kusto.Language DLL"""
        print("Building Kusto.Language DLL...\n")
        
        # Create libs directory
        self.libs_dir.mkdir(exist_ok=True)
        
        # Clean up temp directory if it exists
        if self.temp_dir.exists():
            print(f"Cleaning up existing temp directory: {self.temp_dir}")
            shutil.rmtree(self.temp_dir)
        
        try:
            # Clone the repository
            print("Cloning Kusto-Query-Language repository...")
            subprocess.run([
                'git', 'clone',
                'https://github.com/microsoft/Kusto-Query-Language.git',
                str(self.temp_dir)
            ], check=True)
            print("  [OK] Repository cloned\n")
            
            # Build the DLL
            build_dir = self.temp_dir / "src" / "Kusto.Language"
            print(f"Building DLL from: {build_dir}")
            
            subprocess.run([
                'dotnet', 'build',
                str(build_dir),
                '-c', 'Release'
            ], check=True)
            print("  [OK] Build completed\n")
            
            # Find and copy the DLL
            dll_search_path = build_dir / "bin" / "Release"
            dll_files = list(dll_search_path.rglob("Kusto.Language.dll"))
            
            if not dll_files:
                print("ERROR: Could not find Kusto.Language.dll in build output")
                return False
            
            # Use the first found DLL (should be only one)
            source_dll = dll_files[0]
            target_dll = self.libs_dir / "Kusto.Language.dll"
            
            print(f"Copying DLL from: {source_dll}")
            print(f"            to: {target_dll}")
            shutil.copy2(source_dll, target_dll)
            print("  [OK] DLL copied successfully\n")
            
            # Clean up temp directory
            print("Cleaning up temporary files...")
            shutil.rmtree(self.temp_dir)
            print("  [OK] Cleanup complete\n")
            
            print("="*60)
            print("SUCCESS! Kusto.Language.dll is ready.")
            print(f"Location: {target_dll}")
            print("="*60)
            
            return True
        
        except subprocess.CalledProcessError as e:
            print(f"\nERROR: Build failed: {e}")
            return False
        except Exception as e:
            print(f"\nERROR: Unexpected error: {e}")
            return False
    
    def install_dependencies(self):
        """Install Python dependencies"""
        print("Installing Python dependencies...\n")
        
        requirements_file = self.project_root / "requirements.txt"
        if not requirements_file.exists():
            print("ERROR: requirements.txt not found")
            return False
        
        try:
            subprocess.run([
                sys.executable, '-m', 'pip', 'install', '-r', 
                str(requirements_file)
            ], check=True)
            print("\n  [OK] Dependencies installed\n")
            return True
        except subprocess.CalledProcessError as e:
            print(f"\nERROR: Failed to install dependencies: {e}")
            return False
    
    def verify_installation(self):
        """Verify the installation is working"""
        print("Verifying installation...\n")
        
        # Check if DLL exists
        dll_path = self.libs_dir / "Kusto.Language.dll"
        if not dll_path.exists():
            print(f"  [ERROR] DLL not found at: {dll_path}")
            return False
        print(f"  [OK] DLL found: {dll_path}")
        
        # Try to import pythonnet
        try:
            import clr
            print("  [OK] Python.NET (pythonnet) is installed")
        except ImportError:
            print("  [ERROR] Python.NET (pythonnet) is not installed")
            return False
        
        # Try to load the DLL
        try:
            clr.AddReference(str(dll_path))
            from Kusto.Language import KustoCode
            print("  [OK] Kusto.Language DLL loads successfully")
        except Exception as e:
            print(f"  [ERROR] Failed to load DLL: {e}")
            return False
        
        # Try a simple parse
        try:
            code = KustoCode.Parse("T | take 10")
            diagnostics = code.GetDiagnostics()
            print(f"  [OK] KQL parsing works (found {len(list(diagnostics))} diagnostics)")
        except Exception as e:
            print(f"  [ERROR] KQL parsing failed: {e}")
            return False
        
        print("\n" + "="*60)
        print("Installation verified successfully!")
        print("You can now run: python linter.py <file.yaml>")
        print("="*60)
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description='Setup Sentinel Detection Linter'
    )
    
    parser.add_argument(
        'action',
        choices=['check', 'build-dll', 'install-deps', 'verify', 'full-setup'],
        help='Action to perform'
    )
    
    args = parser.parse_args()
    
    manager = SetupManager()
    
    if args.action == 'check':
        success = manager.check_prerequisites()
    
    elif args.action == 'build-dll':
        if not manager.check_prerequisites():
            return 1
        success = manager.build_dll()
    
    elif args.action == 'install-deps':
        success = manager.install_dependencies()
    
    elif args.action == 'verify':
        success = manager.verify_installation()
    
    elif args.action == 'full-setup':
        print("="*60)
        print("SENTINEL DETECTION LINTER - FULL SETUP")
        print("="*60 + "\n")
        
        if not manager.check_prerequisites():
            return 1
        
        if not manager.install_dependencies():
            return 1
        
        if not manager.build_dll():
            return 1
        
        if not manager.verify_installation():
            return 1
        
        success = True
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
