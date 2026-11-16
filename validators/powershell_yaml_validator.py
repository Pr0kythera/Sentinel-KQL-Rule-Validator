"""
PowerShell YAML Validator

Runs every rule file through PowerShell's ``Get-Content -Raw | ConvertFrom-Yaml``
and reports whatever that second, independent YAML parser has to say, alongside
the findings produced by the other validators.

Why a second parser?
    PyYAML (used by utils/yaml_loader.py) and YamlDotNet (the library behind
    ``ConvertFrom-Yaml``) are different implementations. A file that one accepts
    and the other rejects is worth knowing about, and ``ConvertFrom-Yaml`` is the
    parser many Windows/PowerShell based Sentinel deployment pipelines rely on.

Requirements:
    * PowerShell 7+ (``pwsh``) or Windows PowerShell 5.1 (``powershell``)
    * The third-party ``powershell-yaml`` module. ``ConvertFrom-Yaml`` is NOT a
      built-in cmdlet:   Install-Module powershell-yaml -Scope CurrentUser

Design notes:
    * The PowerShell side lives in powershell/Test-YamlFiles.ps1 and is launched
      with an argument list (never through a shell), so a hostile file name cannot
      inject commands. File paths travel in a JSON list file, not on the command
      line.
    * One PowerShell process handles a whole batch (``prefetch``): spawning pwsh
      and importing the module per file would dominate runtime on large
      detection repositories.
    * The check is opt-in (``--powershell-yaml``) and fails loudly when it was
      requested but cannot run, instead of silently skipping.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .base_validator import BaseValidator

PAYLOAD_MARKER = '@@SENTINEL-LINTER-JSON@@'
SCRIPT_PATH = Path(__file__).resolve().parent / 'powershell' / 'Test-YamlFiles.ps1'
INSTALL_HINT = 'Install-Module powershell-yaml -Scope CurrentUser'

# YamlDotNet messages look like:
#   (Line: 3, Col: 5, Idx: 20) - (Line: 3, Col: 6, Idx: 21): Mapping values are ...
_LOCATION_RE = re.compile(r'\(Line:\s*(\d+),\s*Col:\s*(\d+)')
_LOCATION_PREFIX_RE = re.compile(r'^\(Line:[^)]*\)\s*-\s*\(Line:[^)]*\):\s*')

# runner(cmd, timeout_seconds) -> (returncode, stdout, stderr). Injectable for tests.
Runner = Callable[[List[str], float], Tuple[int, str, str]]


class PowerShellYamlUnavailable(RuntimeError):
    """PowerShell or the powershell-yaml module is not usable on this machine."""


def _subprocess_runner(cmd: List[str], timeout: float) -> Tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return (
        proc.returncode,
        proc.stdout.decode('utf-8', errors='replace'),
        proc.stderr.decode('utf-8', errors='replace'),
    )


def _extract_payload(stdout: str) -> dict:
    """Return the JSON object emitted after the last marker line."""
    marker_pos = stdout.rfind(PAYLOAD_MARKER)
    if marker_pos < 0:
        raise ValueError('marker line not found in PowerShell output')
    body = stdout[marker_pos + len(PAYLOAD_MARKER):].strip()
    if not body:
        raise ValueError('no JSON after marker line in PowerShell output')
    payload = json.loads(body.splitlines()[0])
    if not isinstance(payload, dict):
        raise ValueError('PowerShell JSON payload is not an object')
    return payload


def _as_list(value) -> list:
    """PowerShell may serialise a one-element array as a bare value, or $null."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _tail(text: str, limit: int = 500) -> str:
    text = (text or '').strip()
    return text if len(text) <= limit else '...' + text[-limit:]


class PowerShellYamlValidator(BaseValidator):
    """Validates YAML syntax using PowerShell's ConvertFrom-Yaml."""

    def __init__(self, pwsh_path: Optional[str] = None, timeout: float = 30.0,
                 runner: Optional[Runner] = None):
        """
        Args:
            pwsh_path: Explicit PowerShell executable. Default: ``pwsh`` then
                ``powershell`` from PATH.
            timeout: Seconds allowed PER FILE (a batch gets timeout * files plus a
                fixed start-up allowance).
            runner: Test seam replacing the subprocess call.
        """
        self._pwsh_path = pwsh_path
        self._timeout = float(timeout)
        self._runner = runner or _subprocess_runner
        self._executable: Optional[str] = None
        self._probe: Optional[dict] = None
        self._unavailable_reason: Optional[str] = None
        self._cache: Dict[str, dict] = {}

    @property
    def validator_name(self) -> str:
        return "PowerShell YAML Validator"

    # -- availability ------------------------------------------------------

    def _find_executable(self) -> Optional[str]:
        if self._pwsh_path:
            return shutil.which(self._pwsh_path) or (
                self._pwsh_path if os.path.isfile(self._pwsh_path) else None
            )
        return shutil.which('pwsh') or shutil.which('powershell')

    def _base_command(self) -> List[str]:
        cmd = [self._executable, '-NoLogo', '-NoProfile', '-NonInteractive']
        if os.name == 'nt':
            # Unsigned .ps1 files are blocked by the default policy on Windows
            # PowerShell. The parameter is meaningless on Linux/macOS, so it is
            # only passed on Windows.
            cmd += ['-ExecutionPolicy', 'Bypass']
        cmd += ['-File', str(SCRIPT_PATH)]
        return cmd

    def check_available(self) -> Tuple[bool, str]:
        """
        Verify PowerShell and powershell-yaml are usable.

        Returns (True, description) or (False, reason). The result is cached.
        """
        if self._probe is not None:
            return True, self._describe_probe()
        if self._unavailable_reason is not None:
            return False, self._unavailable_reason

        if not SCRIPT_PATH.is_file():
            return self._unavailable(f'helper script missing: {SCRIPT_PATH}')

        self._executable = self._find_executable()
        if not self._executable:
            where = f"'{self._pwsh_path}'" if self._pwsh_path else "'pwsh' or 'powershell' on PATH"
            return self._unavailable(f'PowerShell executable not found ({where})')

        try:
            rc, out, err = self._runner(self._base_command() + ['-Probe'], 60.0)
        except subprocess.TimeoutExpired:
            return self._unavailable('timed out probing PowerShell (60s)')
        except OSError as exc:
            return self._unavailable(f'could not launch {self._executable}: {exc}')

        try:
            payload = _extract_payload(out)
        except (ValueError, json.JSONDecodeError) as exc:
            return self._unavailable(
                f'unexpected output probing PowerShell ({exc}; exit code {rc}): '
                f'{_tail(err or out)}'
            )

        if not payload.get('moduleFound'):
            return self._unavailable(
                f"the 'powershell-yaml' module is not installed for {self._executable}. "
                f'Install it with: {INSTALL_HINT}'
            )

        self._probe = payload
        return True, self._describe_probe()

    def _unavailable(self, reason: str) -> Tuple[bool, str]:
        self._unavailable_reason = reason
        return False, reason

    def _describe_probe(self) -> str:
        p = self._probe or {}
        return (f"PowerShell {p.get('psVersion', '?')} "
                f"({p.get('psEdition') or 'unknown edition'}), "
                f"powershell-yaml {p.get('moduleVersion', '?')}")

    # -- execution ---------------------------------------------------------

    @staticmethod
    def _key(path: Path) -> str:
        try:
            return str(Path(path).resolve())
        except (OSError, RuntimeError):
            return str(path)

    def prefetch(self, files: Iterable[Path]) -> None:
        """
        Parse many files in a single PowerShell process and cache the results for
        later ``validate`` calls. Safe to call repeatedly; already cached files
        are skipped. Never raises: failures are recorded per file.
        """
        keys = []
        seen = set()
        for f in files:
            k = self._key(f)
            if k not in self._cache and k not in seen:
                seen.add(k)
                keys.append(k)
        if not keys:
            return

        ok, reason = self.check_available()
        if not ok:
            for k in keys:
                self._cache[k] = {'infra_error': f'PowerShell YAML check unavailable: {reason}'}
            return

        list_path = None
        try:
            fd, list_path = tempfile.mkstemp(prefix='sentinel_yaml_', suffix='.json')
            with os.fdopen(fd, 'w', encoding='utf-8') as fh:
                # ensure_ascii keeps the file pure ASCII so PowerShell's encoding
                # defaults cannot corrupt non-ASCII paths.
                json.dump(keys, fh, ensure_ascii=True)

            budget = 30.0 + self._timeout * len(keys)
            try:
                rc, out, err = self._runner(
                    self._base_command() + ['-ListFile', list_path], budget
                )
            except subprocess.TimeoutExpired:
                self._fail_all(keys, f'PowerShell timed out after {budget:.0f}s '
                                     f'parsing {len(keys)} file(s)')
                return
            except OSError as exc:
                self._fail_all(keys, f'could not launch PowerShell: {exc}')
                return

            try:
                payload = _extract_payload(out)
            except (ValueError, json.JSONDecodeError) as exc:
                self._fail_all(
                    keys,
                    f'unexpected PowerShell output ({exc}; exit code {rc}): '
                    f'{_tail(err or out)}'
                )
                return

            if payload.get('fatal'):
                self._fail_all(keys, f"PowerShell script failed: {payload['fatal']}")
                return

            results = _as_list(payload.get('results'))
            if len(results) != len(keys):
                self._fail_all(
                    keys,
                    f'PowerShell returned {len(results)} result(s) for {len(keys)} file(s)'
                )
                return

            for k, entry in zip(keys, results):
                self._cache[k] = entry if isinstance(entry, dict) else {
                    'infra_error': f'malformed result entry: {entry!r}'
                }
        finally:
            if list_path:
                try:
                    os.unlink(list_path)
                except OSError:
                    pass

    def _fail_all(self, keys: List[str], message: str) -> None:
        for k in keys:
            self._cache[k] = {'infra_error': message}

    # -- BaseValidator -----------------------------------------------------

    def validate(self, rule_data: Optional[dict], file_path: Path,
                 all_files: List[Path] = None) -> List[Dict]:
        """
        Args:
            rule_data: Dict parsed by PyYAML, or None when PyYAML could not parse
                the file (the linter still calls this validator in that case, so
                the ConvertFrom-Yaml verdict is reported next to the PyYAML error).
        """
        key = self._key(file_path)
        if key not in self._cache:
            self.prefetch([file_path])
        entry = self._cache.pop(key, {'infra_error': 'no result was produced'})
        return self._findings_for(entry, rule_data)

    # -- result interpretation ---------------------------------------------

    def _findings_for(self, entry: dict, rule_data: Optional[dict]) -> List[Dict]:
        if entry.get('infra_error'):
            return [self.create_error(str(entry['infra_error']))]

        category = entry.get('category')
        pyyaml_ok = isinstance(rule_data, dict)

        if category == 'read-error':
            return [self.create_error(
                f"Get-Content could not read the file: {entry.get('message')}"
            )]

        if category == 'parse-error' or entry.get('ok') is False:
            return [self._parse_error_finding(entry, pyyaml_ok)]

        # ConvertFrom-Yaml succeeded.
        findings: List[Dict] = []

        if entry.get('rootType') is None:
            findings.append(self.create_error(
                'ConvertFrom-Yaml returned no object (file is empty or contains only comments).'
            ))
            return findings

        if not entry.get('isMapping'):
            findings.append(self.create_error(
                f"ConvertFrom-Yaml parsed the root as {entry.get('rootType')}, not a mapping. "
                f"A Sentinel rule must be a YAML mapping at the top level."
            ))
            return findings

        if not pyyaml_ok:
            findings.append(self.create_warning(
                'ConvertFrom-Yaml parsed this file successfully although PyYAML rejected it; '
                'the two parsers disagree (see the YAML Parser error for the PyYAML failure).'
            ))
            return findings

        ps_keys = {str(k) for k in _as_list(entry.get('topLevelKeys'))}
        py_keys = {str(k) for k in rule_data.keys()}
        only_py = sorted(py_keys - ps_keys)
        only_ps = sorted(ps_keys - py_keys)
        if only_py or only_ps:
            parts = []
            if only_py:
                parts.append(f"only seen by PyYAML: {', '.join(only_py)}")
            if only_ps:
                parts.append(f"only seen by ConvertFrom-Yaml: {', '.join(only_ps)}")
            findings.append(self.create_warning(
                'Top-level keys differ between YAML parsers (' + '; '.join(parts) + ').',
                details={'only_pyyaml': only_py, 'only_convertfrom_yaml': only_ps},
            ))
        return findings

    def _parse_error_finding(self, entry: dict, pyyaml_ok: bool) -> Dict:
        chain = [c for c in _as_list(entry.get('errorChain')) if isinstance(c, dict)]
        raw_message = str(entry.get('message') or '').strip()

        line, column = entry.get('line'), entry.get('column')
        if line is None:
            # Fall back to the position embedded in YamlDotNet's message text.
            for source in [raw_message] + [str(c.get('message', '')) for c in reversed(chain)]:
                m = _LOCATION_RE.search(source)
                if m:
                    line, column = int(m.group(1)), int(m.group(2))
                    break

        clean = _LOCATION_PREFIX_RE.sub('', raw_message) or raw_message or 'unknown error'
        where = f' at line {line}, column {column}' if line is not None else ''
        exc_type = chain[-1].get('type') if chain else None
        type_note = f' [{exc_type}]' if exc_type else ''

        if pyyaml_ok:
            message = (f'PyYAML accepted this file but ConvertFrom-Yaml rejected it '
                       f'(the two YAML parsers disagree){where}: {clean}{type_note}')
        else:
            message = f'ConvertFrom-Yaml rejected the file{where}: {clean}{type_note}'

        return self.create_error(
            message,
            details={
                'source': 'ConvertFrom-Yaml',
                'line': line,
                'column': column,
                'parser_disagreement': pyyaml_ok,
                'exception_chain': chain,
            },
        )
