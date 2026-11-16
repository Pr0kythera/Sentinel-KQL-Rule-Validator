"""
Tests for PowerShellYamlValidator.

Real PowerShell is not required: the subprocess boundary is exercised with
(a) an injected runner returning canned JSON, and (b) a fake 'pwsh' executable
that honours the same command-line and JSON contract as
validators/powershell/Test-YamlFiles.ps1. A final integration test runs the real
script and only executes where pwsh and the powershell-yaml module exist.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from validators.powershell_yaml_validator import (
    PAYLOAD_MARKER,
    PowerShellYamlUnavailable,
    PowerShellYamlValidator,
    _extract_payload,
)

ROOT = Path(__file__).resolve().parent.parent
BAD_EXAMPLE = ROOT / "examples" / "yaml_syntax_error.yaml"
GOOD_EXAMPLE = ROOT / "examples" / "valid_detection.yaml"

PROBE_OK = {"psVersion": "7.4.0", "psEdition": "Core", "moduleFound": True,
            "moduleVersion": "0.4.12", "fatal": None, "results": []}


def emit(payload):
    return "noise before marker\n{}\n{}\n".format(PAYLOAD_MARKER, json.dumps(payload))


def parse_error_entry(path="x.yaml", line=3, column=5):
    return {
        "path": path, "ok": False, "category": "parse-error", "isMapping": False,
        "rootType": None, "topLevelKeys": [], "line": line, "column": column,
        "message": "(Line: 3, Col: 5, Idx: 20) - (Line: 3, Col: 6, Idx: 21): "
                   "Mapping values are not allowed in this context.",
        "errorChain": [
            {"type": "System.Management.Automation.MethodInvocationException",
             "message": 'Exception calling "Load" with "1" argument(s): "..."'},
            {"type": "YamlDotNet.Core.SyntaxErrorException",
             "message": "(Line: 3, Col: 5, Idx: 20) - (Line: 3, Col: 6, Idx: 21): "
                        "Mapping values are not allowed in this context."},
        ],
    }


def ok_entry(keys, path="x.yaml"):
    return {"path": path, "ok": True, "category": None, "isMapping": True,
            "rootType": "System.Collections.Hashtable", "topLevelKeys": keys,
            "line": None, "column": None, "message": None, "errorChain": []}


def make_validator(runner=None, **kw):
    return PowerShellYamlValidator(pwsh_path=sys.executable, runner=runner, **kw)


# -- payload extraction ---------------------------------------------------

def test_extract_payload_ignores_noise_and_uses_last_marker():
    out = "banner\n{}\n{{\"a\": 1}}\nmore\n{}\n{{\"a\": 2}}\n".format(PAYLOAD_MARKER, PAYLOAD_MARKER)
    assert _extract_payload(out) == {"a": 2}


@pytest.mark.parametrize("bad", ["", "no marker here", PAYLOAD_MARKER + "\n", PAYLOAD_MARKER + "\n[1, 2]"])
def test_extract_payload_rejects_bad_output(bad):
    with pytest.raises(ValueError):
        _extract_payload(bad)


# -- result interpretation ------------------------------------------------

def test_parse_error_when_pyyaml_failed_reports_location_and_innermost_message():
    f = make_validator()._findings_for(parse_error_entry(), rule_data=None)
    assert len(f) == 1 and f[0]["severity"] == "error"
    msg = f[0]["message"]
    assert "line 3, column 5" in msg
    assert "Mapping values are not allowed in this context." in msg
    assert "YamlDotNet.Core.SyntaxErrorException" in msg
    assert "(Line:" not in msg                      # positional prefix is stripped
    assert "disagree" not in msg
    assert f[0]["details"]["exception_chain"][-1]["type"] == "YamlDotNet.Core.SyntaxErrorException"


def test_parse_error_when_pyyaml_succeeded_flags_disagreement():
    f = make_validator()._findings_for(parse_error_entry(), rule_data={"id": "x"})
    assert "disagree" in f[0]["message"]
    assert f[0]["details"]["parser_disagreement"] is True


def test_location_falls_back_to_message_text_when_start_mark_missing():
    entry = parse_error_entry(line=None, column=None)
    f = make_validator()._findings_for(entry, rule_data=None)
    assert "line 3, column 5" in f[0]["message"]


def test_parse_error_without_any_location_still_reports():
    entry = {"ok": False, "category": "parse-error", "message": "failed to parse scalar 'x' as boolean",
             "errorChain": [{"type": "System.Management.Automation.RuntimeException",
                             "message": "failed to parse scalar 'x' as boolean"}]}
    f = make_validator()._findings_for(entry, rule_data=None)
    assert "failed to parse scalar" in f[0]["message"] and " at line" not in f[0]["message"]


def test_read_error():
    f = make_validator()._findings_for({"category": "read-error", "message": "denied"}, {"a": 1})
    assert f[0]["severity"] == "error" and "denied" in f[0]["message"]


def test_infra_error_is_an_error():
    f = make_validator()._findings_for({"infra_error": "boom"}, {"a": 1})
    assert f[0]["severity"] == "error" and "boom" in f[0]["message"]


def test_clean_parse_with_matching_keys_has_no_findings():
    assert make_validator()._findings_for(ok_entry(["id", "name"]), {"id": 1, "name": 2}) == []


def test_key_mismatch_is_a_warning_listing_both_sides():
    f = make_validator()._findings_for(ok_entry(["id", "extra"]), {"id": 1, "name": 2})
    assert len(f) == 1 and f[0]["severity"] == "warning"
    assert "name" in f[0]["message"] and "extra" in f[0]["message"]


def test_single_key_serialised_as_bare_string_is_tolerated():
    # Windows PowerShell can emit a one-element array as a bare value.
    assert make_validator()._findings_for(ok_entry("id"), {"id": 1}) == []


def test_ps_ok_but_pyyaml_failed_is_a_warning():
    f = make_validator()._findings_for(ok_entry(["id"]), rule_data=None)
    assert f[0]["severity"] == "warning" and "disagree" in f[0]["message"]


def test_empty_document_is_an_error():
    entry = {"ok": True, "rootType": None, "isMapping": False}
    f = make_validator()._findings_for(entry, None)
    assert f[0]["severity"] == "error" and "no object" in f[0]["message"]


def test_non_mapping_root_is_an_error():
    entry = {"ok": True, "rootType": "System.Object[]", "isMapping": False}
    f = make_validator()._findings_for(entry, None)
    assert f[0]["severity"] == "error" and "not a mapping" in f[0]["message"]


# -- availability ---------------------------------------------------------

def test_missing_executable_is_unavailable(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda *_: None)
    v = PowerShellYamlValidator(runner=lambda *a: pytest.fail("must not run"))
    ok, reason = v.check_available()
    assert not ok and "not found" in reason


def test_missing_module_gives_install_hint():
    payload = dict(PROBE_OK, moduleFound=False, moduleVersion=None)
    v = make_validator(runner=lambda cmd, t: (0, emit(payload), ""))
    ok, reason = v.check_available()
    assert not ok and "Install-Module powershell-yaml" in reason


def test_probe_garbage_output_is_unavailable_with_stderr_tail():
    v = make_validator(runner=lambda cmd, t: (1, "", "ParserError: something"))
    ok, reason = v.check_available()
    assert not ok and "ParserError" in reason


def test_probe_timeout_is_unavailable():
    def runner(cmd, t):
        raise subprocess.TimeoutExpired(cmd, t)
    ok, reason = make_validator(runner=runner).check_available()
    assert not ok and "timed out" in reason


def test_available_probe_is_cached():
    calls = []

    def runner(cmd, t):
        calls.append(cmd)
        return 0, emit(PROBE_OK), ""
    v = make_validator(runner=runner)
    assert v.check_available()[0] and v.check_available()[0]
    assert len(calls) == 1


# -- batching and runner plumbing ----------------------------------------

def test_prefetch_uses_one_process_for_many_files_and_cleans_up(tmp_path):
    files = [tmp_path / "a b.yaml", tmp_path / "it's.yaml", tmp_path / "c.yaml"]
    seen = {}

    def runner(cmd, timeout):
        if "-Probe" in cmd:
            return 0, emit(PROBE_OK), ""
        list_file = cmd[cmd.index("-ListFile") + 1]
        seen["cmd"], seen["timeout"] = cmd, timeout
        seen["list_file"] = list_file
        seen["paths"] = json.loads(Path(list_file).read_text(encoding="utf-8"))
        return 0, emit({"fatal": None, "results": [ok_entry(["id"], p) for p in seen["paths"]]}), ""

    v = make_validator(runner=runner, timeout=10)
    v.prefetch(files)
    assert [Path(p).name for p in seen["paths"]] == ["a b.yaml", "it's.yaml", "c.yaml"]
    assert seen["timeout"] == 30 + 10 * 3
    assert not os.path.exists(seen["list_file"])                # temp file removed
    assert "-File" in seen["cmd"] and "-NoProfile" in seen["cmd"]
    # No file path may ever appear on the command line (injection / length safety).
    assert not any(str(tmp_path) in part for part in seen["cmd"])

    # validate() consumes the cache and does not spawn another process
    v._runner = lambda *a: pytest.fail("cache should satisfy validate()")
    assert v.validate({"id": 1}, files[0]) == []


def test_prefetch_count_mismatch_marks_every_file_failed(tmp_path):
    def runner(cmd, t):
        if "-Probe" in cmd:
            return 0, emit(PROBE_OK), ""
        return 0, emit({"fatal": None, "results": []}), ""
    v = make_validator(runner=runner)
    f = tmp_path / "a.yaml"
    out = v.validate({"id": 1}, f)
    assert out[0]["severity"] == "error" and "0 result(s) for 1 file(s)" in out[0]["message"]


def test_script_fatal_is_reported_per_file(tmp_path):
    def runner(cmd, t):
        if "-Probe" in cmd:
            return 0, emit(PROBE_OK), ""
        return 0, emit({"fatal": "Import-Module failed", "results": []}), ""
    out = make_validator(runner=runner).validate({"id": 1}, tmp_path / "a.yaml")
    assert "Import-Module failed" in out[0]["message"]


def test_batch_timeout_is_reported(tmp_path):
    def runner(cmd, t):
        if "-Probe" in cmd:
            return 0, emit(PROBE_OK), ""
        raise subprocess.TimeoutExpired(cmd, t)
    out = make_validator(runner=runner).validate({"id": 1}, tmp_path / "a.yaml")
    assert out[0]["severity"] == "error" and "timed out" in out[0]["message"]


def test_validate_when_unavailable_returns_error_not_exception(tmp_path):
    v = make_validator(runner=lambda cmd, t: (0, emit(dict(PROBE_OK, moduleFound=False)), ""))
    out = v.validate({"id": 1}, tmp_path / "a.yaml")
    assert out[0]["severity"] == "error" and "unavailable" in out[0]["message"]


# -- real subprocess against a fake pwsh honouring the script's contract ----

FAKE_PWSH = textwrap.dedent('''\
    #!{python}
    import json, sys
    import yaml
    M = "@@SENTINEL-LINTER-JSON@@"
    args = sys.argv[1:]
    base = {{"psVersion": "0.0-fake", "psEdition": "Fake", "moduleFound": True,
            "moduleVersion": "0.0", "fatal": None, "results": []}}
    if "-Probe" in args:
        print("profile noise"); print(M); print(json.dumps(base)); sys.exit(0)
    paths = json.load(open(args[args.index("-ListFile") + 1], encoding="utf-8"))
    for p in paths:
        r = {{"path": p, "ok": True, "category": None, "isMapping": False, "rootType": None,
             "topLevelKeys": [], "line": None, "column": None, "message": None, "errorChain": []}}
        try:
            d = yaml.safe_load(open(p, encoding="utf-8"))
            if d is not None:
                r["rootType"] = type(d).__name__
                if isinstance(d, dict):
                    r["isMapping"] = True; r["topLevelKeys"] = [str(k) for k in d]
        except yaml.YAMLError as e:
            m = e.problem_mark
            r.update(ok=False, category="parse-error", line=m.line + 1, column=m.column + 1,
                     message=e.problem,
                     errorChain=[{{"type": "Fake.SyntaxErrorException", "message": e.problem}}])
        base["results"].append(r)
    print(M); print(json.dumps(base))
''')


@pytest.fixture
def fake_pwsh(tmp_path):
    if os.name == "nt":
        pytest.skip("fake pwsh executable is POSIX only")
    pytest.importorskip("yaml")
    exe = tmp_path / "fake-pwsh"
    exe.write_text(FAKE_PWSH.format(python=sys.executable), encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return str(exe)


def test_real_subprocess_plumbing_with_hostile_file_names(fake_pwsh, tmp_path):
    # Names with a space, quote, semicolon, dollar and a unicode char must survive intact.
    bad = tmp_path / "it's $(whoami); é bad.yaml"
    bad.write_text("a: ok\nb: x: y\n", encoding="utf-8")
    good = tmp_path / "good, file.yaml"
    good.write_text("id: 1\nname: n\n", encoding="utf-8")

    v = PowerShellYamlValidator(pwsh_path=fake_pwsh)
    assert v.check_available()[0]
    v.prefetch([bad, good])

    bad_out = v.validate(None, bad)
    assert bad_out and bad_out[0]["severity"] == "error" and "line 2" in bad_out[0]["message"]
    assert v.validate({"id": 1, "name": "n"}, good) == []


def test_linter_reports_powershell_error_alongside_pyyaml_error(fake_pwsh):
    from linter import SentinelLinter
    linter = SentinelLinter(enable_kql_validation=False, enable_powershell_yaml=True,
                            pwsh_path=fake_pwsh)
    result = linter.validate_file(BAD_EXAMPLE)
    validators = {e["validator"] for e in result.errors}
    assert {"YAML Parser", "PowerShell YAML Validator"} <= validators
    assert not result.passed


def test_linter_directory_scan_prefetches_once(fake_pwsh, tmp_path, capsys):
    from linter import SentinelLinter
    (tmp_path / "one.yaml").write_text("id: 1\n", encoding="utf-8")
    (tmp_path / "two.yaml").write_text("id: 2\nbad: a: b\n", encoding="utf-8")
    linter = SentinelLinter(enable_kql_validation=False, enable_powershell_yaml=True,
                            pwsh_path=fake_pwsh)
    results = {r.file_path.name: r for r in linter.validate_directory(tmp_path)}
    assert any(e["validator"] == "PowerShell YAML Validator" for e in results["two.yaml"].errors)
    assert not any(e["validator"] == "PowerShell YAML Validator" for e in results["one.yaml"].errors)


def test_linter_raises_when_requested_but_unavailable(monkeypatch):
    from linter import SentinelLinter
    monkeypatch.setattr(shutil, "which", lambda *_: None)
    with pytest.raises(PowerShellYamlUnavailable):
        SentinelLinter(enable_kql_validation=False, enable_powershell_yaml=True)


def test_linter_without_flag_never_touches_powershell(monkeypatch):
    from linter import SentinelLinter
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("must not spawn"))
    linter = SentinelLinter(enable_kql_validation=False)
    assert linter.powershell_yaml_validator is None
    linter.validate_file(GOOD_EXAMPLE)


# -- optional: real PowerShell + powershell-yaml --------------------------

def _real_validator():
    v = PowerShellYamlValidator()
    ok, reason = v.check_available()
    if not ok:
        pytest.skip("real PowerShell/powershell-yaml unavailable: {}".format(reason))
    return v


def test_real_powershell_rejects_malformed_yaml():
    v = _real_validator()
    out = v.validate(None, BAD_EXAMPLE)
    assert out and out[0]["severity"] == "error"
    assert "ConvertFrom-Yaml rejected the file" in out[0]["message"]


def test_real_powershell_accepts_valid_example():
    v = _real_validator()
    import yaml
    data = yaml.safe_load(GOOD_EXAMPLE.read_text(encoding="utf-8"))
    out = v.validate(data, GOOD_EXAMPLE)
    assert all(f["severity"] != "error" for f in out)
