# Review Findings - Sentinel KQL Rule Validator

Systematic review deliverable for Task 1. Each finding lists a severity
(error / warning / hygiene), a short reproduction, and a fix status.

Status legend:
- FIXED: addressed in this review pass.
- DEFERRED: real finding, but the fix belongs to a later task (2-7) per CLAUDE.md
  (for example the ATT&CK overhaul, KQL semantic rebuild, or example-fixture cleanup
  that CLAUDE.md says to do "after Tasks 2 to 6").
- OPEN DECISION: needs a maintainer choice before it can be actioned.

The linter was exercised after each change: it compiles, runs on the example
files, exits 0 on clean / 1 on failure, and contains no non-ASCII characters in
any tracked source (verified with `grep -rlP '[^\x00-\x7F]'`).

---

## 1a. Repository hygiene and supply chain

### F1. extractor.py is an unrelated PE-malware script - FIXED
- Severity: hygiene / security.
- Repro: `extractor.py` in the repo root imports `pefile`, `pandas`, `numpy`,
  `pickle` and loads `malware_detector.pkl` / `model_columns.pkl`. It is not
  imported by any linter module (`grep -rn extractor --include='*.py'` shows only
  self-references in its own usage strings).
- Risk: `pickle.load` on a shipped model file is arbitrary-code-execution if the
  pickle is ever swapped; it does not belong in a security-tooling repo teams clone
  and run.
- Fix: removed via `git rm extractor.py` after maintainer confirmation. The file was
  committed two commits earlier (0c33767) but is unrelated to the linter and remains
  recoverable from history if needed.

### F2. config/fields_config.py duplicates config/asim_field_names.py - FIXED
- Severity: hygiene.
- Repro: `diff config/fields_config.py config/asim_field_names.py` reported IDENTICAL
  (byte-for-byte). Only `asim_field_names.py` is imported
  (`grep -rn fields_config --include='*.py'` returns nothing).
- Fix: removed `config/fields_config.py` so there is a single source of truth. This
  also removes the duplicated dead `ASIM_PREFIXES` constant (see F13).

### F3. libs/Kusto.Language.dll provenance not recorded - DEFERRED (Task 3)
- Severity: hygiene / supply chain.
- Repro: a 1.8 MB pre-built binary is committed with no recorded version or hash.
- Status: deferred. Task 3 covers pinning the NuGet version and recording/checking a
  SHA-256 at load time.

---

## 1b. Wiring and dead code

### F4. ASIMFieldValidator was never registered - FIXED
- Severity: error (feature silently disabled).
- Repro: `SentinelLinter.__init__` registered Guid/Schema/Entity/Timing/Constraints/
  YAML (+optional KQL) but not `ASIMFieldValidator`; `grep -n ASIMFieldValidator
  linter.py` returned nothing. ASIM column-name checks never ran.
- Fix: imported and registered `ASIMFieldValidator` as an always-on validator. It
  emits warning-level advisories only (it uses `create_warning`), matching the
  recommended severity.

### F5. entity_validator.py defined _find_correct_entity_case twice - FIXED
- Severity: error (shadowing / dead code).
- Repro: two `def _find_correct_entity_case` definitions existed (originally lines
  ~183 and ~198); the second silently shadowed the first.
- Fix: removed the second (less-guarded) definition. The retained implementation
  guards against non-string / empty input and returns the correctly cased entity.

### F6. AFFIRMATIONS list audit - FIXED (see also F10, F11)
- Severity: error (malformed data) + hygiene.
- Repro: the final two entries were `"...that lasts!"` immediately followed by
  `"Wowzers"` with no comma, so Python implicit string concatenation merged them into
  one malformed affirmation.
- Fix: added the missing comma. Additionally the feature is now behind a flag and the
  strings were converted to ASCII (see F10, F11).

### F7. Constant audit in sentinel_constraints_validator.py - NO ACTION NEEDED
- Severity: hygiene.
- Repro/result: every module-level constant is actually enforced by a method:
  `MAX_ENTITY_MAPPINGS` (line 474), `MAX_FIELD_MAPPINGS_PER_ENTITY` (490),
  `MAX_ALERT_PARAMETERS` (619), `MAX_CUSTOM_DETAILS` (518),
  `MAX_CUSTOM_DETAILS_KEY_LENGTH` (544), `MAX_NAME_LENGTH` (338),
  `MAX_DESCRIPTION_LENGTH` (367), `MAX_QUERY_LENGTH` (391),
  `MAX_TRIGGER_THRESHOLD` (203), `MAX_ALERT_NAME_LENGTH` / `MAX_ALERT_DESCRIPTION_LENGTH`
  (580 / 589). None are dead. Minor style note: the key-length check is written as
  `len(key) >= MAX_CUSTOM_DETAILS_KEY_LENGTH + 1` (constant = 19), a roundabout way to
  say "> 19"; left as-is (correct) but flagged.

---

## 1c. Correctness bugs

### F8. KQL output-column extraction is broken - DEFERRED (Task 3)
- Severity: error.
- Repro: `_extract_output_columns` (kql_validator.py) calls `KustoCode.Parse`, which
  performs syntax only, so `code.ResultType` is not reliably populated and the method
  frequently returns an empty set; `_validate_entity_columns` then silently no-ops.
- Status: deferred. Task 3 rebuilds this on `ParseAndAnalyze` + a real `GlobalState`.

### F9. Semantic validation only runs with --schema - DEFERRED (Task 3)
- Severity: error.
- Repro: `self.global_state` is None unless the user passes `--schema`, so misspelled
  fields and unknown tables are never flagged in the common case (kql_validator.py:257).
- Status: deferred. Task 3a builds a useful GlobalState by default.

### F10. Affirmations feature not suitable for a PR gate by default - FIXED
- Severity: hygiene (CI determinism).
- Repro: `print_console_output` printed a random affirmation with 1/5 probability on
  every run, adding non-deterministic noise to CI output.
- Fix: gated behind a new `--affirmations` CLI flag, off by default. Deterministic CI
  output unless explicitly opted in.

### F11. Non-ASCII characters in AFFIRMATIONS - FIXED
- Severity: hygiene (violates the project ASCII-only rule).
- Repro: the AFFIRMATIONS strings used smart apostrophes and em/en dashes
  (`grep -nP '[^\x00-\x7F]' linter.py`).
- Fix: transliterated to ASCII (`'`, `-`). Verified no non-ASCII remains in linter.py.

### F12. datetime.utcnow() is deprecated - FIXED
- Severity: hygiene (deprecation).
- Repro: `print_json_output` used `datetime.utcnow().isoformat() + 'Z'`
  (linter.py:325). `datetime.utcnow()` is deprecated in modern Python.
- Fix: replaced with `datetime.now(timezone.utc).isoformat()` (timezone-aware, keeps a
  UTC offset in the output; verified the JSON timestamp renders as
  `...+00:00`). Imported `timezone`.

### F13. MITRE technique/tactic checks are crude - DEFERRED (Task 2)
- Severity: error.
- Repro: `_is_valid_technique_format` hardcodes the T1000-T1999 range and never checks
  existence; tactics are checked against a hardcoded "v13" list.
- Status: deferred. Task 2 replaces this with validation against real ATT&CK v18.x
  STIX data.

### F14. examples/valid_detection.yaml is not actually valid - DEFERRED (Tasks 2-6)
- Severity: error (fixture).
- Repro: `triggerThreshold:` is null (fails the int check once null-required is
  enforced), `relevantTechniques: ["T1234.001"]` is not a real technique,
  `customDetails` references a column the query never outputs, and the declared tactics
  do not match the technique.
- Status: deferred. CLAUDE.md says to fix fixtures after Tasks 2-6 so "valid" files
  pass cleanly and "invalid" files fail for documented reasons.

---

## 1d. Robustness and error handling

### F15. Broad `except Exception` downgrades real failures - DEFERRED (Task 3)
- Severity: warning.
- Repro: several KQL paths catch `except Exception` and emit a warning or swallow it
  (for example `_validate_semantics`, `_extract_output_columns`), which can hide
  genuine failures on a PR gate.
- Status: deferred to the Task 3 KQL rebuild, which makes failure modes explicit.

### F16. Semantic diagnostics classified by substring matching - DEFERRED (Task 3)
- Severity: warning.
- Repro: `_validate_semantics` decides a diagnostic is "semantic" via
  `'does not exist' in message or 'does not refer' in message or 'type' in
  message.lower()` (kql_validator.py:323) - brittle across library versions/locales.
- Status: deferred. Task 3b uses the diagnostic objects (severity/code), not strings.

---

## Additional findings from the full read (not enumerated in CLAUDE.md)

### F17. Unused imports - FIXED
- Severity: hygiene.
- Repro: `import re` unused in `validators/yaml_validator.py`; `Any` unused in
  `validators/schema_validator.py`; `Optional` unused in `validators/timing_validator.py`.
- Fix: removed all three.

### F18. Non-ASCII in examples/emailbehaviour.yaml - FIXED
- Severity: hygiene (ASCII rule).
- Repro: en-dash in "9AM-5PM" (line 9) and a ">=" glyph in "threshold (>=3)"
  (line 111) - `grep -nP '[^\x00-\x7F]' examples/emailbehaviour.yaml`.
- Fix: replaced with ASCII `-` and `>=`.

### F19. Duplicate GUID across example files - DEFERRED (Tasks 2-6 fixtures)
- Severity: error (fixture).
- Repro: `valid_detection.yaml`, `invalid_detection.yaml`, and
  `example_constraint_errors.yaml` share `id: b1c2d3e4-...901`. When `examples/` is
  scanned together, `GuidValidator` flags `valid_detection.yaml` as a non-unique GUID,
  so it cannot pass. `grep -rn '^id:' examples/`.
- Status: deferred to the fixture cleanup after Tasks 2-6.

### F20. triggerOperator accepts gt/lt/eq - OPEN DECISION
- Severity: warning (spec mismatch).
- Repro: `VALID_TRIGGER_OPERATORS` includes the short forms `gt`, `lt`, `eq`
  (sentinel_constraints_validator.py:24). Real Sentinel analytics-rule YAML accepts
  only `GreaterThan` / `LessThan` / `Equal`. The short forms also make
  `example_constraint_errors.yaml`'s expected error #5 (`triggerOperator: "gt"`) never
  fire, while `valid_detection.yaml` relies on "gt" being accepted.
- Status: not changed. Removing the short forms is a behavior change that also touches
  fixtures; flagged for a maintainer decision (recommended: accept only the long forms
  and update fixtures during the Tasks 2-6 fixture cleanup).

### F21. Present-but-null required fields pass schema validation - DEFERRED (Task 4)
- Severity: warning (validation gap).
- Repro: a required field present with a null value (for example
  `triggerThreshold:`) passes the "field in rule_data" presence check, and both the
  schema type check and the constraints check return early on None.
- Status: deferred. Task 4 tightens required-field handling (null-is-missing) as new
  typed fields are added.

### F22. No test infrastructure exists - DEFERRED (Testing section)
- Severity: error (definition-of-done gap).
- Repro: no `tests/` directory, no `conftest.py`, no pytest config; `pytest` is not in
  `requirements.txt` or `setup.py`.
- Status: deferred. The Testing/acceptance section requires a pytest suite; it will be
  built alongside Tasks 2-6 so each new behavior ships with tests.

### F23. Minor validator limitations - DEFERRED / NOTED
- Severity: hygiene.
- `YAMLValidator` duplicate-key detection recurses into nested mappings but not into
  list items, and can report the same duplicate more than once.
- `GuidValidator._is_valid_guid` uses `uuid.UUID`, which accepts non-canonical forms
  (no hyphens, braces, uppercase) despite the canonical-format error message.
- Status: noted for future hardening; not blocking.

---

## Summary of changes made in this pass

- Removed the duplicate `config/fields_config.py` (F2).
- Registered `ASIMFieldValidator` as a warning-level validator (F4).
- Removed the shadowing duplicate `_find_correct_entity_case` (F5).
- Fixed the missing comma in AFFIRMATIONS, converted the list to ASCII, and gated the
  feature behind `--affirmations` (default off) (F6, F10, F11).
- Replaced deprecated `datetime.utcnow()` with `datetime.now(timezone.utc)` (F12).
- Removed three unused imports (F17).
- Removed non-ASCII characters from `examples/emailbehaviour.yaml` (F18).

## Open items requiring a maintainer decision

- F20: drop `gt`/`lt`/`eq` from valid trigger operators? (still open)
- The larger Tasks 2-7 involve network fetches (ATT&CK STIX bundle, Sentinel table
  schemas), DLL provenance pinning, and several design choices flagged in CLAUDE.md
  (customDetails shape, a `lastReviewed` field, DET/AN/DC severity, environment
  allow-list). These are tracked separately and should be scheduled deliberately.
