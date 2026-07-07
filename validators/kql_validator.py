"""
KQL Validator

Validates KQL queries using the Microsoft Kusto.Language library via Python.NET.

Key facts this implementation relies on (Kusto.Language API):
- KustoCode.Parse(query) performs syntax analysis only.
- KustoCode.ParseAndAnalyze(query, globals) performs semantic analysis: it
  populates code.ResultType (a TableSymbol) and produces semantic diagnostics
  (unknown column/table, type errors) when the referenced tables are described
  by the supplied GlobalState.
- code.GetDiagnostics() returns diagnostics carrying Severity, Message, Start,
  and Length. We classify by Severity, not by substring-matching the message.

A useful GlobalState is always constructed from a bundled Sentinel table schema
(config.schema_definition.SENTINEL_SCHEMA), optionally extended by a --schema
override and by a rule's declared `tables:` (added as open/loose symbols so
column references against unknown tables do not hard-fail analysis).

NOTE: On a machine without a working .NET runtime, the DLL cannot load and this
validator raises at construction; the linter then disables KQL validation and
the pytest suite skips the KQL tests. The logic below is written against the
documented API and has not been exercised end-to-end on the current machine.
"""

import hashlib
import json
import platform
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from .base_validator import BaseValidator
from config.schema_definition import SENTINEL_SCHEMA

# Constructs that make the output column set indeterminate. When present we
# degrade column-membership checks to warnings rather than emit false errors.
_INDETERMINATE_PATTERNS = [
    re.compile(r'\bsearch\b', re.IGNORECASE),
    re.compile(r'\bevaluate\b', re.IGNORECASE),
    re.compile(r'\bbag_unpack\b', re.IGNORECASE),
    re.compile(r'\bpivot\b', re.IGNORECASE),
    re.compile(r'\bmv-expand\b', re.IGNORECASE),
    re.compile(r'\bproject-away\b', re.IGNORECASE),
    re.compile(r'\bproject-keep\b', re.IGNORECASE),
    re.compile(r'\bunion\b[^|]*\*', re.IGNORECASE),
]

_SEARCH_RE = re.compile(r'(^|\|)\s*search\b', re.IGNORECASE)
_TIMEGENERATED_RE = re.compile(r'\bTimeGenerated\b')


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
            schema_config: Optional schema override merged on top of the bundled
                Sentinel schema. Format:
                {
                    "database": "SecurityDB",
                    "tables": {
                        "SecurityEvent": {"columns": {"TimeGenerated": "datetime", ...}}
                    }
                }
        """
        self.schema_config = schema_config

        # Load DLL and initialize type handles.
        self._load_kusto_dll()

        # Always build a usable GlobalState: bundled schema, extended by any
        # override. Built once per instance (the linter reuses one instance).
        merged = self._merge_schema(SENTINEL_SCHEMA, schema_config)
        self.global_state = self._build_global_state(merged)

    # -- schema / GlobalState --------------------------------------------------

    @staticmethod
    def _merge_schema(base: dict, override: Optional[dict]) -> dict:
        """Merge an override schema on top of the bundled base schema."""
        merged = {
            "database": base.get("database", "SecurityInsights"),
            "tables": dict(base.get("tables", {})),
        }
        if override:
            if override.get("database"):
                merged["database"] = override["database"]
            for name, table_def in override.get("tables", {}).items():
                merged["tables"][name] = table_def
        return merged

    def _build_global_state(self, schema_config: dict):
        """Build a GlobalState from a schema dict, or None on failure."""
        try:
            table_symbols = [
                self._table_symbol(name, table_def.get("columns", {}))
                for name, table_def in schema_config.get("tables", {}).items()
            ]
            db_name = schema_config.get("database", "SecurityInsights")
            db_symbol = self._DatabaseSymbol(db_name, *table_symbols)
            return self._GlobalState.Default.WithDatabase(db_symbol)
        except Exception as exc:  # noqa: BLE001 - .NET interop guard
            print("Warning: Failed to build GlobalState: {}".format(exc))
            return None

    def _table_symbol(self, name: str, columns: dict):
        """Create a closed TableSymbol from a {col: type} mapping."""
        column_defs = ", ".join("{}: {}".format(c, t) for c, t in columns.items())
        return self._TableSymbol(name, "({})".format(column_defs))

    def _open_table_symbol(self, name: str):
        """Create an open/loose TableSymbol that tolerates unknown columns."""
        try:
            return self._TableSymbol(name).WithIsOpen(True)
        except Exception:  # noqa: BLE001 - fall back to an empty closed table
            return self._TableSymbol(name, "()")

    def _state_with_declared_tables(self, tables) -> Tuple[object, List[str]]:
        """
        Return a GlobalState augmented with any declared tables not already in
        the base schema (added as open symbols), plus the list of names that
        were unknown (so the caller can warn about limited semantic checking).
        """
        if not tables or not isinstance(tables, list) or self.global_state is None:
            return self.global_state, []

        known = set(self.schema_config.get("tables", {}).keys()) if self.schema_config else set()
        known |= set(SENTINEL_SCHEMA.get("tables", {}).keys())
        unknown = [t for t in tables if isinstance(t, str) and t not in known]
        if not unknown:
            return self.global_state, []

        try:
            base = self._merge_schema(SENTINEL_SCHEMA, self.schema_config)
            symbols = [
                self._table_symbol(name, table_def.get("columns", {}))
                for name, table_def in base["tables"].items()
            ]
            symbols.extend(self._open_table_symbol(name) for name in unknown)
            db_symbol = self._DatabaseSymbol(base["database"], *symbols)
            return self._GlobalState.Default.WithDatabase(db_symbol), unknown
        except Exception:  # noqa: BLE001
            return self.global_state, unknown

    # -- DLL loading + integrity ----------------------------------------------

    def _verify_dll_integrity(self, dll_path: Path):
        """
        Compare the DLL's SHA-256 to the pinned value and warn on mismatch.
        Integrity is advisory (a warning), not a hard failure, so a legitimately
        updated DLL plus a stale pin does not break all linting.
        """
        pinned_file = dll_path.parent / "kusto_dll_pinned.json"
        if not pinned_file.exists():
            return
        try:
            pinned = json.loads(pinned_file.read_text(encoding="utf-8"))
            expected = pinned.get("sha256")
            actual = hashlib.sha256(dll_path.read_bytes()).hexdigest()
            if expected and actual != expected:
                print("WARNING: Kusto.Language.dll sha256 does not match the pinned "
                      "value in {}. Expected {}, got {}.".format(
                          pinned_file.name, expected, actual))
        except Exception:  # noqa: BLE001 - integrity check must never crash load
            pass

    def _load_kusto_dll(self):
        """Load Kusto.Language DLL via Python.NET."""
        if KQLValidator._dll_loaded:
            return

        try:
            self._configure_runtime()

            try:
                import clr
            except Exception as e:
                raise ImportError(
                    "Python.NET not installed. Install with: pip install pythonnet\n"
                    "Original error: {}".format(e)
                )

            dll_path = self._find_dll_path()
            if not dll_path:
                raise FileNotFoundError(
                    "Kusto.Language.dll not found in expected locations."
                )

            try:
                dll_absolute = dll_path.resolve()
            except (OSError, RuntimeError) as e:
                raise FileNotFoundError(
                    "Cannot resolve DLL path {}: {}".format(dll_path, e))

            if not dll_absolute.exists():
                raise FileNotFoundError(
                    "Kusto.Language.dll not found at resolved path: {}".format(dll_absolute))

            self._verify_dll_integrity(dll_absolute)

            import System
            assembly = System.Reflection.Assembly.LoadFrom(str(dll_absolute))
            assembly_name = assembly.GetName().Name
            clr.AddReference(assembly_name)

            from Kusto.Language import KustoCode
            from Kusto.Language.Symbols import GlobalState, DatabaseSymbol, TableSymbol

            KQLValidator._KustoCode = KustoCode
            KQLValidator._GlobalState = GlobalState
            KQLValidator._DatabaseSymbol = DatabaseSymbol
            KQLValidator._TableSymbol = TableSymbol
            KQLValidator._dll_loaded = True

        except ImportError:
            raise
        except Exception as e:
            raise Exception("Failed to load Kusto.Language DLL: {}".format(e))

    def _configure_runtime(self):
        """Configure Python.NET runtime based on platform."""
        if platform.system() in ["Linux", "Darwin"]:
            try:
                from pythonnet import load
                load("coreclr")
            except Exception as e:
                raise RuntimeError(
                    "Failed to configure .NET runtime for {}. Ensure .NET runtime is "
                    "installed (brew install --cask dotnet on macOS, or "
                    "https://dotnet.microsoft.com/download). Error: {}".format(
                        platform.system(), e)
                )

    def _find_dll_path(self) -> Optional[Path]:
        """Find Kusto.Language.dll in common locations."""
        possible_paths = [
            Path(__file__).parent.parent / "libs" / "Kusto.Language.dll",
            Path("libs") / "Kusto.Language.dll",
            Path("Kusto.Language.dll"),
        ]
        for path in possible_paths:
            if path.exists():
                return path
        return possible_paths[0]

    # -- validation entry ------------------------------------------------------

    def validate(self, rule_data: dict, file_path: Path,
                 all_files: List[Path] = None) -> List[Dict]:
        errors = []

        query = rule_data.get('query')
        if not query:
            return errors  # missing query handled by schema validator
        if not isinstance(query, str):
            errors.append(self.create_error(
                "Field 'query' must be a string, got {}".format(type(query).__name__),
                field='query'
            ))
            return errors

        # Syntax first.
        syntax_errors = self._validate_syntax(query)
        errors.extend(syntax_errors)
        if any(e.get('severity') == 'error' for e in syntax_errors):
            # Semantic analysis and column extraction are unreliable on a query
            # that does not parse; stop here.
            return errors

        # Build a GlobalState that includes any declared tables as open symbols.
        state, unknown_tables = self._state_with_declared_tables(rule_data.get('tables'))
        for name in unknown_tables:
            errors.append(self.create_warning(
                "Table '{}' has no bundled schema; only limited semantic checking "
                "was possible for it.".format(name),
                field='tables'
            ))

        # Semantic diagnostics (misspelled fields, unknown tables/columns).
        errors.extend(self._validate_semantics(query, state, syntax_errors))

        # Extract output columns once and share the result across checks.
        output_columns, indeterminate = self._extract_output_columns(query, state)

        errors.extend(self._validate_entity_columns(
            rule_data, output_columns, indeterminate))
        errors.extend(self._validate_custom_details_columns(
            rule_data, output_columns, indeterminate))

        # Advisory performance/cost checks.
        errors.extend(self._validate_query_style(query))

        return errors

    # -- syntax / semantics ----------------------------------------------------

    def _validate_syntax(self, query: str) -> List[Dict]:
        errors = []
        try:
            code = self._KustoCode.Parse(query)
            for diag in code.GetDiagnostics():
                severity = str(diag.Severity).lower()
                message = str(diag.Message)
                excerpt = self._get_query_excerpt(query, diag.Start, diag.Length)
                if severity == 'error':
                    errors.append(self.create_error(
                        "KQL syntax error: {}. Issue at position {}: '{}'".format(
                            message, diag.Start, excerpt),
                        field='query'
                    ))
                elif severity == 'warning':
                    errors.append(self.create_warning(
                        "KQL syntax warning: {}".format(message), field='query'))
        except Exception as e:  # noqa: BLE001
            errors.append(self.create_error(
                "Failed to parse KQL query: {}".format(e), field='query'))
        return errors

    def _validate_semantics(self, query: str, state, syntax_errors: List[Dict]) -> List[Dict]:
        """Report semantic diagnostics by severity, deduped against syntax."""
        errors = []
        if state is None:
            return errors
        try:
            code = self._KustoCode.ParseAndAnalyze(query, state)
            # Keys of diagnostics already reported by the syntax pass.
            seen = set()
            for diag in self._KustoCode.Parse(query).GetDiagnostics():
                seen.add((diag.Start, diag.Length, str(diag.Message)))

            for diag in code.GetDiagnostics():
                key = (diag.Start, diag.Length, str(diag.Message))
                if key in seen:
                    continue  # already reported as syntax
                severity = str(diag.Severity).lower()
                message = str(diag.Message)
                excerpt = self._get_query_excerpt(query, diag.Start, diag.Length)
                if severity == 'error':
                    errors.append(self.create_error(
                        "KQL semantic error: {}. Issue at position {}: '{}'".format(
                            message, diag.Start, excerpt),
                        field='query'
                    ))
                elif severity == 'warning':
                    errors.append(self.create_warning(
                        "KQL semantic warning: {}".format(message), field='query'))
        except Exception as e:  # noqa: BLE001 - surface loudly, do not swallow
            errors.append(self.create_warning(
                "KQL semantic analysis could not run: {}".format(e), field='query'))
        return errors

    # -- output column extraction ---------------------------------------------

    def _extract_output_columns(self, query: str, state) -> Tuple[set, Optional[str]]:
        """
        Return (output_columns, indeterminate_reason).

        indeterminate_reason is None when the output column set is reliable, or a
        human-readable string explaining why membership checks should soften to
        warnings (open result type, indeterminate constructs, or analysis error).
        """
        # Textual heuristic for constructs that yield a dynamic/open column set.
        for pattern in _INDETERMINATE_PATTERNS:
            if pattern.search(query):
                return set(), (
                    "query uses a construct that produces an indeterminate output "
                    "column set (for example search, union *, evaluate, mv-expand, "
                    "bag_unpack, or project-away/keep)")

        if state is None:
            return set(), "no table schema available to analyze the query"

        try:
            code = self._KustoCode.ParseAndAnalyze(query, state)
            result_type = getattr(code, 'ResultType', None)
            if result_type is None:
                return set(), "the query result type could not be determined"

            # An open result type has an unknown/extensible column set.
            if getattr(result_type, 'IsOpen', False):
                return set(), "the query result type is open (columns not fully known)"

            columns = set()
            if hasattr(result_type, 'Columns'):
                for column in result_type.Columns:
                    if hasattr(column, 'Name'):
                        columns.add(str(column.Name))
            if not columns:
                return set(), "no output columns were resolved for the query"
            return columns, None
        except Exception as e:  # noqa: BLE001
            return set(), "output column extraction failed: {}".format(e)

    @staticmethod
    def _match_column(name: str, output_columns: set) -> Tuple[str, Optional[str]]:
        """Return ('exact'|'case'|'missing', correct_cased_name_or_None)."""
        if name in output_columns:
            return 'exact', name
        lowered = name.lower()
        for col in output_columns:
            if col.lower() == lowered:
                return 'case', col
        return 'missing', None

    # -- Task 6: entity columnName membership ---------------------------------

    def _validate_entity_columns(self, rule_data: dict, output_columns: set,
                                 indeterminate: Optional[str]) -> List[Dict]:
        errors = []
        entity_mappings = rule_data.get('entityMappings')
        if not entity_mappings or not isinstance(entity_mappings, list):
            return errors

        for idx, entity in enumerate(entity_mappings):
            if not isinstance(entity, dict):
                continue
            entity_type = entity.get('entityType')
            field_mappings = entity.get('fieldMappings', [])
            if not isinstance(field_mappings, list):
                continue
            for field_idx, field_mapping in enumerate(field_mappings):
                if not isinstance(field_mapping, dict):
                    continue
                column_name = field_mapping.get('columnName')
                if not column_name or not isinstance(column_name, str):
                    continue
                field = 'entityMappings[{}].fieldMappings[{}].columnName'.format(
                    idx, field_idx)
                errors.extend(self._column_membership_result(
                    column_name, output_columns, indeterminate, field,
                    "Entity '{}'".format(entity_type)))
        return errors

    # -- Task 5: customDetails column membership ------------------------------

    def _validate_custom_details_columns(self, rule_data: dict, output_columns: set,
                                         indeterminate: Optional[str]) -> List[Dict]:
        errors = []
        custom_details = rule_data.get('customDetails')
        if not custom_details or not isinstance(custom_details, dict):
            return errors
        for key, column_name in custom_details.items():
            if not isinstance(column_name, str) or not column_name:
                continue
            field = 'customDetails.{}'.format(key)
            errors.extend(self._column_membership_result(
                column_name, output_columns, indeterminate, field,
                "customDetails '{}'".format(key)))
        return errors

    def _column_membership_result(self, column_name: str, output_columns: set,
                                  indeterminate: Optional[str], field: str,
                                  subject: str) -> List[Dict]:
        """Shared three-way outcome for column-membership checks (Tasks 5, 6)."""
        if indeterminate:
            return [self.create_warning(
                "{} references column '{}' but output columns could not be "
                "determined ({}); check skipped.".format(subject, column_name, indeterminate),
                field=field
            )]
        outcome, correct = self._match_column(column_name, output_columns)
        if outcome == 'exact':
            return []
        if outcome == 'case':
            return [self.create_error(
                "{} references column '{}' but the query outputs it as '{}' "
                "(case must match exactly).".format(subject, column_name, correct),
                field=field
            )]
        available = ', '.join(sorted(output_columns)) if output_columns else '(none)'
        return [self.create_error(
            "{} references column '{}' which is not in the query output. "
            "Available columns: {}".format(subject, column_name, available),
            field=field
        )]

    # -- Task 3d: advisory style checks ---------------------------------------

    def _validate_query_style(self, query: str) -> List[Dict]:
        errors = []
        if _SEARCH_RE.search(query):
            errors.append(self.create_warning(
                "Query uses 'search', which scans broadly and can be expensive in a "
                "scheduled rule. Prefer targeting specific tables and columns.",
                field='query'
            ))
        if not _TIMEGENERATED_RE.search(query):
            errors.append(self.create_warning(
                "Query does not reference 'TimeGenerated'. Scheduled rules usually "
                "constrain the time window explicitly; confirm this is intended.",
                field='query'
            ))
        return errors

    # -- helpers ---------------------------------------------------------------

    def _get_query_excerpt(self, query: str, start: int, length: int) -> str:
        try:
            end = min(start + length, len(query))
            excerpt = query[start:end].strip()
            if len(excerpt) > 50:
                excerpt = excerpt[:47] + "..."
            return excerpt
        except Exception:  # noqa: BLE001
            return "<error extracting excerpt>"
