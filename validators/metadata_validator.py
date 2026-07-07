"""
Metadata Validator (Task 4)

Value, format, and cross-field checks for the new rule metadata fields. Presence
and type are enforced by the schema validator; this validator owns the semantics:

- author: a valid ASCII email address.
- creationDate: exact 'YYYY-MM-DDTHH:MM:SS' format, and must be in the past (UTC).
- reviewDate: same format; must be at least one year (365-day approximation) after
  creationDate. Warns when reviewDate is in the past (review overdue).
- environment: non-empty string; optionally constrained to an allow-list.
- tables: non-empty list of unique non-empty strings; warns when a declared table
  is never mentioned in the query text (best-effort, textual).

Date handling uses UTC consistently (the safer choice for CI). The one-year rule
uses a documented 365-day approximation rather than calendar arithmetic to avoid
adding a dateutil dependency.
"""

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Optional

from .base_validator import BaseValidator

# Pragmatic ASCII email pattern (not full RFC 5322): local-part, @, domain with
# at least one dot, no spaces.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S"
_ONE_YEAR_DAYS = 365


class MetadataValidator(BaseValidator):
    """Validates author, creationDate, reviewDate, environment, and tables."""

    def __init__(self, environment_allowlist: Optional[list] = None):
        """
        Args:
            environment_allowlist: optional list of permitted environment values.
                When None (default), any non-empty string passes.
        """
        self.environment_allowlist = environment_allowlist

    @property
    def validator_name(self) -> str:
        return "Metadata Validator"

    def validate(self, rule_data: dict, file_path: Path,
                 all_files: List[Path] = None) -> List[Dict]:
        errors = []
        errors.extend(self._validate_author(rule_data))
        creation_dt = None
        creation_errors, creation_dt = self._validate_creation_date(rule_data)
        errors.extend(creation_errors)
        errors.extend(self._validate_review_date(rule_data, creation_dt))
        errors.extend(self._validate_environment(rule_data))
        errors.extend(self._validate_tables(rule_data))
        return errors

    # -- author ---------------------------------------------------------------

    def _validate_author(self, rule_data) -> List[Dict]:
        author = rule_data.get('author')
        if author is None:
            return []  # presence handled by schema validator
        if not isinstance(author, str) or not author.strip():
            return [self.create_error(
                "Field 'author' must be a non-empty string containing an email address.",
                field='author')]
        if not _EMAIL_RE.match(author):
            return [self.create_error(
                "Field 'author' value '{}' is not a valid email address.".format(author),
                field='author')]
        return []

    # -- dates ----------------------------------------------------------------

    def _parse_dt(self, value):
        """Return (datetime_or_None, error_message_or_None)."""
        if not isinstance(value, str) or not value.strip():
            return None, "must be a non-empty string"
        try:
            return datetime.strptime(value, _DATETIME_FORMAT), None
        except ValueError:
            return None, ("must match format 'YYYY-MM-DDTHH:MM:SS' "
                          "(for example 2026-07-07T12:12:00)")

    def _now_utc_naive(self):
        # Compare naive datetimes consistently in UTC.
        return datetime.now(timezone.utc).replace(tzinfo=None)

    def _validate_creation_date(self, rule_data):
        value = rule_data.get('creationDate')
        if value is None:
            return [], None
        dt, err = self._parse_dt(value)
        if err:
            return [self.create_error(
                "Field 'creationDate' {}.".format(err), field='creationDate')], None
        if dt > self._now_utc_naive():
            return [self.create_error(
                "Field 'creationDate' '{}' is in the future; it must be in the past.".format(value),
                field='creationDate')], dt
        return [], dt

    def _validate_review_date(self, rule_data, creation_dt):
        value = rule_data.get('reviewDate')
        if value is None:
            return []
        dt, err = self._parse_dt(value)
        if err:
            return [self.create_error(
                "Field 'reviewDate' {}.".format(err), field='reviewDate')]

        errors = []
        # Overdue warning (independent of creationDate).
        if dt < self._now_utc_naive():
            errors.append(self.create_warning(
                "Field 'reviewDate' '{}' is in the past; the review is overdue.".format(value),
                field='reviewDate'))

        # One-year rule relative to creationDate (baseline decision: creationDate).
        if creation_dt is not None:
            minimum = creation_dt + timedelta(days=_ONE_YEAR_DAYS)
            if dt < minimum:
                errors.append(self.create_error(
                    "Field 'reviewDate' '{}' must be at least one year (~365 days) "
                    "after creationDate '{}'.".format(
                        value, creation_dt.strftime(_DATETIME_FORMAT)),
                    field='reviewDate'))
        return errors

    # -- environment ----------------------------------------------------------

    def _validate_environment(self, rule_data) -> List[Dict]:
        env = rule_data.get('environment')
        if env is None:
            return []
        if not isinstance(env, str) or not env.strip():
            return [self.create_error(
                "Field 'environment' must be a non-empty string.", field='environment')]
        if self.environment_allowlist and env not in self.environment_allowlist:
            allowed = ', '.join(self.environment_allowlist)
            return [self.create_error(
                "Field 'environment' value '{}' is not in the allowed set: {}".format(
                    env, allowed),
                field='environment')]
        return []

    # -- tables ---------------------------------------------------------------

    def _validate_tables(self, rule_data) -> List[Dict]:
        tables = rule_data.get('tables')
        if tables is None:
            return []
        if not isinstance(tables, list):
            return [self.create_error(
                "Field 'tables' must be a list of strings.", field='tables')]

        errors = []
        if len(tables) == 0:
            errors.append(self.create_error(
                "Field 'tables' must not be empty.", field='tables'))

        seen = set()
        for idx, table in enumerate(tables):
            if not isinstance(table, str) or not table.strip():
                errors.append(self.create_error(
                    "Table at index {} must be a non-empty string.".format(idx),
                    field='tables[{}]'.format(idx)))
                continue
            if table in seen:
                errors.append(self.create_error(
                    "Table '{}' is declared more than once in 'tables'.".format(table),
                    field='tables[{}]'.format(idx)))
            seen.add(table)

        # Best-effort cross-check: warn when a declared table is never mentioned
        # in the query text. The reverse check (query references a table not
        # declared) requires KQL semantic analysis and is handled by the KQL
        # validator when a .NET runtime is available.
        query = rule_data.get('query')
        if isinstance(query, str):
            for table in seen:
                if not re.search(r'\b{}\b'.format(re.escape(table)), query):
                    errors.append(self.create_warning(
                        "Declared table '{}' is not referenced anywhere in the "
                        "query.".format(table),
                        field='tables'))
        return errors
