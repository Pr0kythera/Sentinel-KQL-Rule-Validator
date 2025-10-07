"""
File Scanner
Scans directories for YAML files.
"""

from pathlib import Path
from typing import List


def scan_yaml_files(directory: Path, recursive: bool = True) -> List[Path]:
    """
    Scan directory for YAML files.
    
    Args:
        directory: Directory to scan
        recursive: Whether to scan subdirectories recursively
    
    Returns:
        List of Path objects for YAML files
    """
    yaml_files = []
    
    if recursive:
        # Recursively find all YAML files
        yaml_files.extend(directory.rglob('*.yaml'))
        yaml_files.extend(directory.rglob('*.yml'))
    else:
        # Only search immediate directory
        yaml_files.extend(directory.glob('*.yaml'))
        yaml_files.extend(directory.glob('*.yml'))
    
    # Sort for consistent ordering
    yaml_files.sort()
    
    return yaml_files
