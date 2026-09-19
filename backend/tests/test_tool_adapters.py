"""Phase 5 external tool adapter tests (parse + state machine, no binaries)."""
from __future__ import annotations

import json
import subprocess
from unittest import mock

import pytest

from app.observations import types
from app.tools.adapters import registry
from app.tools.adapters.base import ToolObservation, ToolParseError, redact_command, safe_target
from app.tools.scanner_tools import (
    STATE_COMPLETED,
    STATE_EXECUTION_FAILED,
    STATE_NOT_INSTALLED,
    STATE_PARSE_FAILED,
)
from app.tools.adapters.ffuf import FfufAdapter
from app.tools.adapters.httpx import HttpxAdapter
from app.tools.adapters.nikto import NiktoAdapter
from app.tools.adapters.nmap import NmapAdapter
from app.tools.adapters.nuclei import NucleiAdapter
from app.tools.adapters.sqlmap import SqlmapAdapter
from app.tools.adapters.testssl import TestsslAdapter


EXPECTED_TOOLS = {"nmap", "nuclei", "httpx", "ffuf", "nikto", "sqlmap", "testssl"}


def test_registry_covers_expected_tools_and_capabilities():
    assert set(registry.ADAPTERS) == EXPECTED_TOOLS
    for name, adapter in registry.ADAPTERS.items():
        assert adapter.tool_name == name
        assert adapter.declared_capabilities, name
    ffuf = registry.adapters_for_capability("directory_fuzzing")
    assert [a.tool_name for a in ffuf] == ["ffuf"]
    assert registry.get_adapter("missing") is None


def test_nmap_parses_host_port_service():
    xml = """<nmaprun><host><address addr="10.0.0.5" addrtype="ipv4"/>
    <hostnames><hostname name="web.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="22"><state state="filtered"/>
        <service name="ssh"/></port>
    </ports></host></nmaprun>"""
    obs = NmapAdapter().parse(xml, "10.0.0.5")
    kinds = [o.observation_type for o in obs]
    assert kinds.count(types.OBS_HOST) == 1
    assert kinds.count(types.OBS_PORT) == 2
    assert kinds.count(types.OBS_SERVICE) == 2
    assert all(o.subject == "web.local" for o in obs)
    https = next(o for o in obs if o.data.get("port") == 443 and o.observation_type == types.OBS_SERVICE)
    assert https.data["product"] == "nginx"


def test_nmap_malformed_output_raises_parse_error():
    with pytest.raises(ToolParseError):
        NmapAdapter().parse("nmap: command not found", "host")


def test_nuclei_parses_jsonl_findings():
    record = {
        "template-id": "CVE-2021-1234",
        "matched-at": "https://x.test/admin",
        "info": {
            "name": "Exposed admin", "severity": "high",
            "classification": {"cve-id": ["CVE-2021-1234"]},
            "tags": ["admin"],
        },
    }
    obs = NucleiAdapter().parse(json.dumps(record), "x.test")
    assert len(obs) == 1
    assert obs[0].observation_type == types.OBS_VULNERABILITY
    assert obs[0].subject == "https://x.test/admin"
    assert obs[0].data["severity"] == "High"
    assert obs[0].data["cve"] == "CVE-2021-1234"


def test_nuclei_blank_output_yields_no_observations():
    assert NucleiAdapter().parse("\n  \n", "x.test") == []


def test_httpx_parses_response_and_technology():
    line = json.dumps({
        "url": "https://x.test", "status_code": 200, "title": "Home",
        "webserver": "nginx", "tech": ["React", "Vite"],
    })
    obs = HttpxAdapter().parse(line, "x.test")
    assert obs[0].observation_type == types.OBS_HTTP_RESPONSE
    assert obs[0].data["status_code"] == 200
    techs = [o.data["technology"] for o in obs if o.observation_type == types.OBS_TECHNOLOGY]
    assert techs == ["React", "Vite"]


def test_ffuf_parses_results_and_requires_wordlist():
    payload = {"results": [{"url": "https://x.test/admin", "status": 200,
                            "length": 42, "input": {"FUZZ": "admin"}}]}
    obs = FfufAdapter().parse(json.dumps(payload), "x.test")
    assert obs[0].observation_type == types.OBS_HTTP_ENDPOINT
    assert obs[0].data["input"] == {"FUZZ": "admin"}
    command = FfufAdapter().build_command("https://x.test", {"wordlist": "w.txt", "output": "o.json"})
    assert "-w" in command and "w.txt" in command
    with pytest.raises(ToolParseError):
        FfufAdapter().build_command("https://x.test", {})


def test_nikto_parses_plain_and_banner_prefixed_json():
    payload = {"vulnerabilities": [{"id": "999103", "msg": "Outdated server", "url": "/"}]}
    obs = NiktoAdapter().parse(json.dumps(payload), "x.test")
    assert obs[0].observation_type == types.OBS_VULNERABILITY
    assert obs[0].data["message"] == "Outdated server"
    prefixed = "- Nikto v2.5\n" + json.dumps(payload)
    assert len(NiktoAdapter().parse(prefixed, "x.test")) == 1


def test_sqlmap_only_reports_injectable_parameters():
    injectable = (
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind\n"
        "    Payload: id=1 AND 1234=1234\n"
    )
    obs = SqlmapAdapter().parse(injectable, "https://x.test/?id=1")
    assert len(obs) == 1
    assert obs[0].data["parameter"] == "id"
    assert obs[0].data["types"] == ["boolean-based blind"]

    negative = "[INFO] all tested parameters do not appear to be injectable\n"
    assert SqlmapAdapter().parse(negative, "https://x.test/?id=1") == []


def test_testssl_parses_certificates_and_findings():
    payload = [
        {"id": "cert_commonName", "finding": "x.test", "severity": "INFO"},
        {"id": "cert_expirationStatus", "finding": "expired", "severity": "HIGH"},
        {"id": "SSLv3", "finding": "offered", "severity": "HIGH"},
        {"id": "service", "finding": "443", "severity": "OK"},
    ]
    obs = TestsslAdapter().parse(json.dumps(payload), "x.test")
    certs = [o for o in obs if o.observation_type == types.OBS_CERTIFICATE]
    findings = [o for o in obs if o.observation_type == types.OBS_VULNERABILITY]
    assert len(certs) == 2
    assert len(findings) == 1
    assert findings[0].data["severity"] == "High"


def test_run_reports_not_installed_and_simulation_without_observations():
    adapter = NmapAdapter()
    with mock.patch.object(adapter, "installed_binary", return_value=None):
        result = adapter.run("10.0.0.1")
    assert result.status == STATE_NOT_INSTALLED
    assert result.observations == []
    assert result.installed is False

    sim = NmapAdapter().run("10.0.0.1", simulation=True)
    assert sim.status == STATE_COMPLETED
    assert sim.observations == []


def test_run_rejects_forbidden_options():
    result = SqlmapAdapter().run("https://x.test/?id=1", options={"parameter": "id", "dump": True})
    assert result.status == STATE_EXECUTION_FAILED
    assert "forbidden" in (result.error or "")


def test_run_maps_parse_failure_to_state():
    adapter = HttpxAdapter()
    completed = subprocess.CompletedProcess(args=["httpx"], returncode=0, stdout="not json", stderr="")
    with mock.patch.object(adapter, "installed_binary", return_value="httpx"), \
         mock.patch("app.tools.adapters.base.subprocess.run", return_value=completed):
        result = adapter.run("x.test")
    assert result.status == STATE_PARSE_FAILED
    assert result.observations == []
    assert result.raw_output == "not json"


def test_run_success_parses_stdout():
    adapter = HttpxAdapter()
    line = json.dumps({"url": "https://x.test", "status_code": 200})
    completed = subprocess.CompletedProcess(args=["httpx"], returncode=0, stdout=line, stderr="")
    with mock.patch.object(adapter, "installed_binary", return_value="httpx"), \
         mock.patch("app.tools.adapters.base.subprocess.run", return_value=completed):
        result = adapter.run("x.test")
    assert result.status == STATE_COMPLETED
    assert len(result.observations) == 1
    assert result.exit_code == 0


def test_helper_redaction_and_target_safety():
    command = ["nuclei", "-target", "x.test", "--header", "Authorization: Bearer abc"]
    redacted = redact_command(command)
    assert redacted[-1] == "<REDACTED>"
    assert "abc" not in " ".join(redacted)
    cleaned = safe_target("http://x.test/a?b=1\n; rm -rf /")
    assert "\n" not in cleaned and ";" not in cleaned
    assert cleaned.startswith("http://x.test/a?b=1")


def test_observation_builds_redacted_observation_kwargs():
    obs = ToolObservation(
        types.OBS_VULNERABILITY, "x.test",
        data={"token": "supersecret", "note": "Bearer abc"},
    )
    kwargs = obs.to_observation_data(scan_id=7, tool_name="nuclei", user_id="u1", target="x.test")
    assert kwargs["scan_id"] == 7
    assert kwargs["source"] == types.SOURCE_EXTERNAL_TOOL
    assert kwargs["observation_type"] == types.OBS_VULNERABILITY
    assert kwargs["data_json"]["token"] == "<REDACTED>"
    assert "abc" not in kwargs["data_json"]["note"]


def test_observation_rejects_unknown_type():
    with pytest.raises(ValueError):
        ToolObservation("not_a_type", "x.test")
