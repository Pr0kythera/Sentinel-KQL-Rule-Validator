"""
YAML Loader
Safely loads and parses YAML files.
"""

import yaml
from pathlib import Path
from typing import Dict


class YAMLLoadError(Exception):
    """Custom exception for YAML loading errors"""
    pass


def load_yaml_file(file_path: Path) -> Dict:
    """
    Safely load a YAML file.
    
    Args:
        file_path: Path to the YAML file
    
    Returns:
        Parsed YAML data as dictionary
    
    Raises:
        YAMLLoadError: If the file cannot be loaded or parsed
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if data is None:
            raise YAMLLoadError(f"File is empty or contains only comments: {file_path}")
        
        if not isinstance(data, dict):
            raise YAMLLoadError(
                f"YAML file must contain a dictionary at root level, got {type(data).__name__}"
            )
        
        return data
    
    except yaml.YAMLError as e:
        # Parse YAML-specific errors
        if hasattr(e, 'problem_mark'):
            mark = e.problem_mark
            raise YAMLLoadError(
                f"YAML parsing error at line {mark.line + 1}, column {mark.column + 1}: {e.problem}"
            )
        else:
            raise YAMLLoadError(f"YAML parsing error: {str(e)}")
    
    except FileNotFoundError:
        raise YAMLLoadError(f"File not found: {file_path}")
    
    except PermissionError:
        raise YAMLLoadError(f"Permission denied reading file: {file_path}")
    
    except Exception as e:
        raise YAMLLoadError(f"Error loading YAML file: {str(e)}")
