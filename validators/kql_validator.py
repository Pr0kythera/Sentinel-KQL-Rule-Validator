"""
KQL Validator
Validates KQL queries using Microsoft Kusto.Language library via Python.NET.
"""

import platform
from pathlib import Path
from typing import List, Dict, Optional

from .base_validator import BaseValidator


class KQLValidator(BaseValidator):
    """Validates KQL queries using Microsoft Kusto.Language"""
    
    _dll_loaded = False
    _KustoCode = None
    _GlobalState = None
    _DatabaseSymbol = None
    _TableSymbol = None
    
    @property
    def validator_name(self) -> str:
        return "KQL Validator"
    
    def __init__(self, schema_config: dict = None):
        """
        Initialize KQL validator.
        
        Args:
            schema_config: Optional schema configuration for semantic validation
                Format: {
                    "database": "SecurityDB",
                    "tables": {
                        "SecurityEvent": {
                            "columns": {"TimeGenerated": "datetime", "Computer": "string", ...}
                        }
                    }
                }
        """
        self.schema_config = schema_config
        self.global_state = None
        
        # Load DLL and initialize
        self._load_kusto_dll()
        
        # Build GlobalState if schema provided
        if schema_config:
            self.global_state = self._build_global_state(schema_config)

    def _load_kusto_dll(self):
        """Load Kusto.Language DLL via Python.NET"""
        if KQLValidator._dll_loaded:
            return  # Already loaded
        
        try:
            # Configure runtime for platform BEFORE importing clr
            # This must happen first on macOS/Linux
            self._configure_runtime()
            
            # Import Python.NET AFTER runtime is configured
            try:
                import clr
            except Exception as e:
                # Only treat this as pythonnet missing
                raise ImportError(
                    "Python.NET not installed. Install with: pip install pythonnet\n"
                    f"Original error: {e}"
                )
            
            # Find the DLL path
            dll_path = self._find_dll_path()
            if not dll_path:
                raise FileNotFoundError(
                    "Kusto.Language.dll not found in expected locations.\n"
                    "Please build the DLL using: python [setup.py](http://_vscodecontentref_/18) build-dll"
                )
            
            # Resolve to absolute path first (critical for cross-platform compatibility)
            try:
                dll_absolute = dll_path.resolve()
            except (OSError, RuntimeError) as e:
                raise FileNotFoundError(f"Cannot resolve DLL path {dll_path}: {e}")
            
            # Now check if the resolved path exists
            if not dll_absolute.exists():
                raise FileNotFoundError(
                    f"Kusto.Language.dll not found at resolved path: {dll_absolute}\n"
                    "Please build the DLL using: python [setup.py](http://_vscodecontentref_/19) build-dll"
                )
            
            # Use Assembly.LoadFrom to load the physical DLL file
            import System
            assembly = System.Reflection.Assembly.LoadFrom(str(dll_absolute))
            
            # Register the loaded assembly with Python.NET using its simple name
            assembly_name = assembly.GetName().Name
            clr.AddReference(assembly_name)
            
            # Attempt direct imports first
            try:
                from Kusto.Language import KustoCode
                from Kusto.Language.Symbols import GlobalState, DatabaseSymbol, TableSymbol
                
                KQLValidator._KustoCode = KustoCode
                KQLValidator._GlobalState = GlobalState
                KQLValidator._DatabaseSymbol = DatabaseSymbol
                KQLValidator._TableSymbol = TableSymbol
                KQLValidator._dll_loaded = True
                return
            except Exception as import_err:
                # Fallback: probe assembly types and import using discovered namespace
                try:
                    available = [t.FullName for t in assembly.GetTypes()]
                except Exception:
                    available = []
                
                def _import_type_by_shortname(shortname: str):
                    matches = [t for t in available if t.endswith(f".{shortname}")]
                    if not matches:
                        return None
                    full_name = matches[0]
                    parts = full_name.split('.')
                    ns = '.'.join(parts[:-1])
                    type_name = parts[-1]
                    try:
                        module = __import__(ns, fromlist=[type_name])
                        return getattr(module, type_name)
                    except Exception:
                        return None
                
                # Try to resolve each required type
                KustoCode = None
                try:
                    from Kusto.Language import KustoCode as _kc
                    KustoCode = _kc
                except Exception:
                    KustoCode = _import_type_by_shortname("KustoCode") or _import_type_by_shortname("Kusto.Language.KustoCode")
                
                GlobalState = _import_type_by_shortname("GlobalState")
                DatabaseSymbol = _import_type_by_shortname("DatabaseSymbol")
                TableSymbol = _import_type_by_shortname("TableSymbol")
                
                # If KustoCode still not found, try to import top-level type name
                if not KustoCode:
                    # try any type that ends with "KustoCode"
                    kc_matches = [t for t in available if t.endswith(".KustoCode")]
                    if kc_matches:
                        parts = kc_matches[0].split('.')
                        ns = '.'.join(parts[:-1])
                        try:
                            module = __import__(ns, fromlist=[parts[-1]])
                            KustoCode = getattr(module, parts[-1])
                        except Exception:
                            KustoCode = None
                
                if not (KustoCode and GlobalState and DatabaseSymbol and TableSymbol):
                    sample = available[:10]
                    raise Exception(
                        f"Failed to import required Kusto types from assembly. "
                        f"Import error: {import_err}. Sample assembly types: {sample}"
                    )
                
                KQLValidator._KustoCode = KustoCode
                KQLValidator._GlobalState = GlobalState
                KQLValidator._DatabaseSymbol = DatabaseSymbol
                KQLValidator._TableSymbol = TableSymbol
                KQLValidator._dll_loaded = True
            
        except ImportError:
            # re-raise ImportError (already handled above for pythonnet missing)
            raise
        except Exception as e:
            raise Exception(f"Failed to load Kusto.Language DLL: {e}")
  
    def _configure_runtime(self):
        """Configure Python.NET runtime based on platform"""
        if platform.system() in ["Linux", "Darwin"]:
            # Use CoreCLR on Linux/Mac (must be done before importing clr)
            try:
                from pythonnet import load
                load("coreclr")
            except Exception as e:
                # Re-raise with more helpful message
                raise RuntimeError(
                    f"Failed to configure .NET runtime for {platform.system()}. "
                    f"Ensure .NET runtime is installed: brew install --cask dotnet (macOS) "
                    f"or visit https://dotnet.microsoft.com/download. Error: {e}"
                )
    
    def _find_dll_path(self) -> Optional[Path]:
        """Find Kusto.Language.dll in common locations"""
        possible_paths = [
            # Relative to validators directory
            Path(__file__).parent.parent / "libs" / "Kusto.Language.dll",
            # Relative to current directory
            Path("libs") / "Kusto.Language.dll",
            # In current directory
            Path("Kusto.Language.dll"),
        ]
        
        for path in possible_paths:
            if path.exists():
                return path
        
        return possible_paths[0]  # Return default expected path
    
    def _build_global_state(self, schema_config: dict):
        """Build GlobalState from schema configuration"""
        try:
            table_symbols = []
            
            for table_name, table_def in schema_config.get('tables', {}).items():
                columns = table_def.get('columns', {})
                
                # Build column definition string
                column_defs = [f"{col_name}: {col_type}" 
                             for col_name, col_type in columns.items()]
                column_str = f"({', '.join(column_defs)})"
                
                # Create TableSymbol
                table_symbol = self._TableSymbol(table_name, column_str)
                table_symbols.append(table_symbol)
            
            # Create DatabaseSymbol
            db_name = schema_config.get('database', 'default')
            db_symbol = self._DatabaseSymbol(db_name, *table_symbols)
            
            # Build GlobalState
            return self._GlobalState.Default.WithDatabase(db_symbol)
        
        except Exception as e:
            print(f"Warning: Failed to build GlobalState: {e}")
            return None
    
    def validate(self, rule_data: dict, file_path: Path, all_files: List[Path] = None) -> List[Dict]:
        """Validate KQL query"""
        errors = []
        
        query = rule_data.get('query')
        if not query:
            # Query field missing - but this will be caught by schema validator
            return errors
        
        if not isinstance(query, str):
            errors.append(self.create_error(
                f"Field 'query' must be a string, got {type(query).__name__}",
                field='query'
            ))
            return errors
        
        # Perform syntax validation
        syntax_errors = self._validate_syntax(query)
        errors.extend(syntax_errors)
        
        # If syntax is valid and we have schema, do semantic validation
        if not syntax_errors and self.global_state:
            semantic_errors = self._validate_semantics(query)
            errors.extend(semantic_errors)
        
        # Validate entity columns exist in query output
        if not syntax_errors:
            entity_errors = self._validate_entity_columns(query, rule_data)
            errors.extend(entity_errors)
        
        return errors
    
    def _validate_syntax(self, query: str) -> List[Dict]:
        """Validate KQL syntax"""
        errors = []
        
        try:
            # Parse the query
            code = self._KustoCode.Parse(query)
            
            # Get diagnostics
            diagnostics = code.GetDiagnostics()
            
            for diag in diagnostics:
                severity = str(diag.Severity).lower()
                message = str(diag.Message)
                start = diag.Start
                length = diag.Length
                
                # Extract problematic code snippet
                query_excerpt = self._get_query_excerpt(query, start, length)
                
                if severity == 'error':
                    errors.append(self.create_error(
                        f"KQL syntax error: {message}. Issue at position {start}: '{query_excerpt}'",
                        field='query'
                    ))
                elif severity == 'warning':
                    errors.append(self.create_warning(
                        f"KQL syntax warning: {message}",
                        field='query'
                    ))
        
        except Exception as e:
            errors.append(self.create_error(
                f"Failed to parse KQL query: {str(e)}",
                field='query'
            ))
        
        return errors
    
    def _validate_semantics(self, query: str) -> List[Dict]:
        """Validate KQL semantics with schema"""
        errors = []
        
        try:
            # Parse with semantic analysis
            code = self._KustoCode.ParseAndAnalyze(query, self.global_state)
            
            # Get diagnostics
            diagnostics = code.GetDiagnostics()
            
            for diag in diagnostics:
                severity = str(diag.Severity).lower()
                message = str(diag.Message)
                
                # Only report semantic errors (skip syntax errors already reported)
                if 'does not exist' in message or 'does not refer' in message or 'type' in message.lower():
                    if severity == 'error':
                        errors.append(self.create_error(
                            f"KQL semantic error: {message}",
                            field='query'
                        ))
                    elif severity == 'warning':
                        errors.append(self.create_warning(
                            f"KQL semantic warning: {message}",
                            field='query'
                        ))
        
        except Exception as e:
            # Semantic validation failed, but don't fail the entire validation
            errors.append(self.create_warning(
                f"Semantic validation failed: {str(e)}",
                field='query'
            ))
        
        return errors
    
    def _validate_entity_columns(self, query: str, rule_data: dict) -> List[Dict]:
        """Validate that entity mapping columns exist in query output"""
        errors = []
        
        entity_mappings = rule_data.get('entityMappings', [])
        if not entity_mappings:
            return errors
        
        try:
            # Extract output columns from query
            output_columns = self._extract_output_columns(query)
            
            if not output_columns:
                # Could not extract columns, skip validation
                return errors
            
            # Check each entity mapping
            for idx, entity in enumerate(entity_mappings):
                entity_type = entity.get('entityType')
                field_mappings = entity.get('fieldMappings', [])
                
                for field_idx, field_mapping in enumerate(field_mappings):
                    column_name = field_mapping.get('columnName')
                    
                    if column_name and column_name not in output_columns:
                        available = ', '.join(sorted(output_columns))
                        errors.append(self.create_error(
                            f"Entity mapping for '{entity_type}' references column '{column_name}' "
                            f"which is not present in query output. Available columns: {available}",
                            field=f'entityMappings[{idx}].fieldMappings[{field_idx}].columnName'
                        ))
        
        except Exception as e:
            # Column extraction failed, add warning but don't fail validation
            errors.append(self.create_warning(
                f"Could not validate entity columns: {str(e)}",
                field='entityMappings'
            ))
        
        return errors
    
    def _extract_output_columns(self, query: str) -> set:
        """Extract final output columns from KQL query"""
        columns = set()
        
        try:
            # Parse the query
            code = self._KustoCode.Parse(query)
            
            # Get the result type (columns in the output)
            if hasattr(code, 'ResultType') and code.ResultType:
                result_type = code.ResultType
                
                # Extract column names
                if hasattr(result_type, 'Columns'):
                    for column in result_type.Columns:
                        if hasattr(column, 'Name'):
                            columns.add(str(column.Name))
        
        except Exception:
            # If extraction fails, return empty set
            pass
        
        return columns
    
    def _get_query_excerpt(self, query: str, start: int, length: int) -> str:
        """Extract problematic portion of query"""
        try:
            end = min(start + length, len(query))
            excerpt = query[start:end].strip()
            
            # Limit excerpt length
            if len(excerpt) > 50:
                excerpt = excerpt[:47] + "..."
            
            return excerpt
        except Exception:
            return "<error extracting excerpt>"
