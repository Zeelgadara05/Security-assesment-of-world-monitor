"""Phase 7 tool execution: one runner for every tool kind.

Three kinds run through this module:

  * **Phase 5 adapters** (nmap, httpx + opt-in natools) -- normalized
    ``ToolObservation`` output is persisted through the shared observation
    pipeline; a bounded runner enforces the timeout and cooperative
    cancellation.  ``timeout`` / ``Execution Failed`` attempts are retried once.
  * **legacy scanner shells** (subfinder, assetfinder, dnsx, gau, whatweb,
    nuclei) -- the Phase 3 CLI wrappers are reused verbatim so real nuclei
    ``-json`` output still becomes ``nuclei_finding`` observations.
  * **stdlib probes** (real_dns, real_tcp, real_http) -- always available,
    real facts only.

Every attempt is recorded in ``tool_executions``; every terminal attempt also
writes the legacy ``ToolResult`` row so all existing consumers (SSE, UI,
coverage) keep working.  Nothing here fabricates success for a tool that did
not run.
"""
from __future__ import annotations

import datetime
import time

from app.observations import types as obs_types
from app.orchestration.stages import TOOL_TO_STAGE, enabled as stage_enabled
from app.tools import real_probes
from app.tools import scanner_tools
from app.tools.adapters.registry import get_adapter

_EXTRAS = ("ffuf", "nikto", "sqlmap", "testssl")

_LEGACY_RUNNERS = {
    "subfinder": lambda target: scanner_tools.run_subfinder(target, simulation=False),
    "assetfinder": lambda target: scanner_tools.run_assetfinder(target, simulation=False),
    "gau": lambda target: scanner_tools.run_gau(target, simulation=False),
    "whatweb": lambda target: scanner_tools.run_whatweb(target, simulation=False),
    "nuclei": lambda target: scanner_tools.run_nuclei(target, simulation=False),
    "dnsx": lambda target: scanner_tools.run_dnsx(target, [], simulation=False),
}

_LOG_MAX = 12000


def clip(text: str, limit: int = _LOG_MAX) -> str:
    text = text or ""
    return text[:limit] + ("\n...[truncated]" if len(text) > limit else "")


def _save_result(db, scan_id: int, tool_name: str, result: dict):
    """Write the legacy ToolResult row (Phase 4 consumers) without committing."""
    from database.models import ToolResult

    raw_output = result.get("log", "")
    status_map = {
        "success": "Completed",
        scanner_tools.STATE_NOT_INSTALLED: scanner_tools.STATE_NOT_INSTALLED,
        scanner_tools.STATE_TIMEOUT: scanner_tools.STATE_TIMEOUT,
        scanner_tools.STATE_PARSE_FAILED: scanner_tools.STATE_PARSE_FAILED,
        scanner_tools.STATE_EXECUTION_FAILED: "Failed",
        "skipped": "Skipped",
        "Completed": "Completed",
    }
    status = status_map.get(result.get("status"), "Failed")
    db.add(ToolResult(
        scan_id=scan_id,
        tool_name=tool_name,
        status=status,
        raw_output=clip(raw_output),
    ))


def _begin_execution(db, scan, tool: str, attempt: int) -> object:
    from database.models import ToolExecution

    ex = ToolExecution(
        scan_id=scan.id,
        stage=TOOL_TO_STAGE.get(tool, "VALIDATION"),
        tool=tool,
        adapter=_adapter_kind(tool),
        attempt=attempt,
        status="running",
        target=scan.target,
        started_at=datetime.datetime.utcnow(),
    )
    db.add(ex)
    db.flush()
    return ex


def _adapter_kind(tool: str) -> str:
    if tool == "real_dns":
        return "native_probe"
    if get_adapter(tool) is not None:
        return "adapter"
    return "legacy"


def _finish_execution(db, ex, *, status: str, duration_ms: int,
                      parsed_observations: int = 0, command_redacted: list = (),
                      exit_code: int | None = None, stdout_size: int | None = None,
                      stderr_size: int | None = None, stdout_truncated: bool = False,
                      stderr_truncated: bool = False, cancellation_state: str | None = None,
                      termination_reason: str | None = None, error_code: str | None = None):
    from database.models import ToolExecution

    ex.status = status
    ex.finished_at = datetime.datetime.utcnow()
    ex.duration_ms = duration_ms
    ex.parsed_observations = parsed_observations
    ex.command_redacted = " ".join(command_redacted) if command_redacted else None
    ex.exit_code = exit_code
    ex.stdout_size = stdout_size
    ex.stderr_size = stderr_size
    ex.stdout_truncated = bool(stdout_truncated)
    ex.stderr_truncated = bool(stderr_truncated)
    ex.cancellation_state = cancellation_state
    ex.termination_reason = termination_reason
    ex.error_code = error_code
    db.flush()


def _persist_adapter_observations(db, scan, tool: str, target: str,
                                  observations) -> int:
    from database.models import Observation

    count = 0
    for obs in observations:
        kwargs = obs.to_observation_data(
            scan_id=scan.id,
            tool_name=tool,
            source=obs_types.SOURCE_EXTERNAL_TOOL,
            target=target,
            asset=None,
        )
        db.add(Observation(**kwargs))
        db.flush()
        count += 1
    return count


def _persist_legacy_observation(db, scan, *, kind: str, subject: str,
                                data: dict, raw: str):
    from database.models import Observation

    db.add(Observation(
        scan_id=scan.id,
        tool_name="nuclei",
        kind=kind,
        subject=(subject or scan.target)[:255],
        data_json=data or {},
        raw_output=raw or "",
    ))
    db.flush()


def _extra_options(config: dict, tool: str) -> dict:
    return dict((config or {}).get("tool_options", {}).get(tool) or {})


def execute_tool(db, scan, tool: str, config: dict, job, state: dict) -> dict:
    """Run one planned tool and return its Phase 3-shaped summary dict."""
    from app.orchestration import events

    attempt = 0
    if not stage_enabled(config, tool):
        _save_result(db, scan.id, tool, {"tool": tool, "status": "skipped",
                                         "log": f"[{tool}] DISABLED by scan configuration."})
        ex = _begin_execution(db, scan, tool, 1)
        _finish_execution(db, ex, status="skipped", duration_ms=0)
        events.emit_tool(db, scan.id, tool, "skipped", attempt=1)
        return {"tool": tool, "status": "skipped"}

    if job is not None:
        from app.workers.tasks import ScanCancelled
        if job.is_cancelled():
            raise ScanCancelled()

    started = time.monotonic()

    if tool == "real_dns":
        return _run_dns_probe(db, scan, tool, config, job, state, started)
    if tool == "real_tcp":
        return _run_tcp_probe(db, scan, tool, config, job, state, started)
    if tool == "real_http":
        return _run_http_probe(db, scan, tool, config, job, state, started)
    if tool in _LEGACY_RUNNERS:
        return _run_legacy(db, scan, tool, config, job, started)
    if get_adapter(tool) is not None:
        return _run_adapter(db, scan, tool, config, job, started)
    return {"tool": tool, "status": scanner_tools.STATE_EXECUTION_FAILED}


# ---------------------------------------------------------------------------
# stdlib probes
# ---------------------------------------------------------------------------
def _run_dns_probe(db, scan, tool, config, job, state, started) -> dict:
    from app.orchestration import events

    hosts = state.get("hosts") or [scan.target]
    observations = []
    status = "success"
    for host in hosts:
        report = real_probes.dns_probe(host)
        observations.extend(report.get("observations", []))
    duration_ms = int((time.monotonic() - started) * 1000)
    ex = _begin_execution(db, scan, tool, 1)
    _persist_observations(db, scan, tool, observations)
    _finish_execution(db, ex, status="completed", duration_ms=duration_ms,
                      parsed_observations=len(observations))
    log = f"[real_dns] {len(observations)} DNS observation(s) recorded for {len(hosts)} host(s)."
    _save_result(db, scan.id, tool, {"status": status, "log": log})
    events.emit_tool(db, scan.id, tool, "completed", attempt=1,
                     detail={"observations": len(observations)})
    return {"tool": tool, "status": status, "observations": observations, "log": log}


def _run_tcp_probe(db, scan, tool, config, job, state, started) -> dict:
    from app.orchestration import events

    hosts = state.get("hosts") or [scan.target]
    observations = []
    for host in hosts:
        report = real_probes.tcp_probe(host)
        observations.extend(report.get("observations", []))
    duration_ms = int((time.monotonic() - started) * 1000)
    ex = _begin_execution(db, scan, tool, 1)
    _persist_observations(db, scan, tool, observations)
    open_ports = sum(1 for o in observations if o.get("kind") == "tcp_open")
    _finish_execution(db, ex, status="completed", duration_ms=duration_ms,
                      parsed_observations=len(observations))
    log = f"[real_tcp] {open_ports} open port(s); {len(observations)} observation(s)."
    _save_result(db, scan.id, tool, {"status": "success", "log": log})
    events.emit_tool(db, scan.id, tool, "completed", attempt=1,
                     detail={"observations": len(observations), "open_ports": open_ports})
    return {"tool": tool, "status": "success", "observations": observations, "log": log}


def _run_http_probe(db, scan, tool, config, job, state, started) -> dict:
    from app.orchestration import events

    hosts = state.get("hosts") or [scan.target]
    observations = []
    for host in hosts:
        for scheme in ("https", "http"):
            observations.extend(real_probes.http_probe(f"{scheme}://{host}").get("observations", []))
    duration_ms = int((time.monotonic() - started) * 1000)
    ex = _begin_execution(db, scan, tool, 1)
    _persist_observations(db, scan, tool, observations)
    _finish_execution(db, ex, status="completed", duration_ms=duration_ms,
                      parsed_observations=len(observations))
    log = f"[real_http] {len(observations)} HTTP observation(s) recorded."
    _save_result(db, scan.id, tool, {"status": "success", "log": log})
    events.emit_tool(db, scan.id, tool, "completed", attempt=1,
                     detail={"observations": len(observations)})
    return {"tool": tool, "status": "success", "observations": observations, "log": log}


def _persist_observations(db, scan, tool: str, observations: list):
    from database.models import Observation

    for o in observations:
        db.add(Observation(
            scan_id=scan.id,
            tool_name=tool,
            kind=(o.get("kind") or "probe_fact"),
            subject=o.get("subject") or scan.target,
            data_json=o.get("data") or {},
            raw_output=clip(o.get("raw") or ""),
        ))
    db.flush()


# ---------------------------------------------------------------------------
# legacy scanner shells
# ---------------------------------------------------------------------------
def _run_legacy(db, scan, tool, config, job, started) -> dict:
    from app.orchestration import events

    target = scan.target
    result = _LEGACY_RUNNERS[tool](target)
    duration_ms = int((time.monotonic() - started) * 1000)
    status = result.get("status") or ""
    terminal = _legacy_terminal(status)

    # nuclei real output -> nuclei_finding observations (exactly Phase 3).
    parsed = 0
    if tool == "nuclei" and status == "success":
        for record in result.get("vulnerabilities") or []:
            _persist_legacy_observation(
                db, scan,
                kind="nuclei_finding",
                subject=record.get("matched_at") or record.get("proof_of_concept") or target,
                data={
                    "title": record.get("title"),
                    "severity": record.get("severity"),
                    "cve": record.get("cve"),
                    "cvss": record.get("cvss"),
                    "owasp": record.get("owasp"),
                    "cwe": record.get("cwe"),
                    "description": record.get("description"),
                    "remediation": record.get("remediation"),
                    "matched_at": record.get("matched_at"),
                    "template_id": record.get("template_id"),
                },
                raw=record.get("proof_of_concept") or result.get("log") or "")
            parsed += 1

    ex = _begin_execution(db, scan, tool, 1)
    err = result.get("error")
    _finish_execution(
        db, ex,
        status=terminal["execution"],
        duration_ms=duration_ms,
        parsed_observations=parsed,
        error_code=terminal["code"],
        termination_reason=err,
        command_redacted=[tool] + result.get("command", []),
    )
    _save_result(db, scan.id, tool, result)
    events.emit_tool(db, scan.id, tool, terminal["event"], attempt=1,
                     detail={"parsed_observations": parsed})
    return dict(result, duration_ms=duration_ms)


def _legacy_terminal(status: str) -> dict:
    if status == "success":
        return {"execution": "completed", "event": "completed", "code": None}
    if status == scanner_tools.STATE_NOT_INSTALLED:
        return {"execution": "not_installed", "event": "not_installed", "code": "not_installed"}
    if status == scanner_tools.STATE_TIMEOUT:
        return {"execution": "timeout", "event": "timeout", "code": "timeout"}
    if status == scanner_tools.STATE_PARSE_FAILED:
        return {"execution": "parse_failed", "event": "parse_failed", "code": "parse_failed"}
    return {"execution": "failed", "event": "failed", "code": "execution_failed"}


# ---------------------------------------------------------------------------
# Phase 5 adapters (bounded + retry on transient failures only)
# ---------------------------------------------------------------------------
_TRANSIENT_STATUSES = (scanner_tools.STATE_TIMEOUT, scanner_tools.STATE_EXECUTION_FAILED)


def _run_adapter(db, scan, tool, config, job, started) -> dict:
    from app.orchestration import events

    adapter = get_adapter(tool)
    if tool in _EXTRAS:
        options = _extra_options(config, tool)
        if not options:
            _save_result(db, scan.id, tool, {
                "tool": tool, "status": "skipped",
                "log": f"[{tool}] opt-in tool has no safe tool_options configured; not scanning blind.",
            })
            ex = _begin_execution(db, scan, tool, 1)
            _finish_execution(db, ex, status="skipped", duration_ms=0)
            events.emit_tool(db, scan.id, tool, "skipped", attempt=1)
            return {"tool": tool, "status": "skipped"}
    else:
        options = _adapter_default_options(tool)

    max_attempts = 2
    last = None
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        ex = _begin_execution(db, scan, tool, attempts)
        events.emit_tool(db, scan.id, tool, "started", stage=TOOL_TO_STAGE.get(tool),
                         attempt=attempts, detail={"attempt": attempts})
        cancel_check = job.cancel_check if job is not None else None
        result = adapter.run(
            scan.target, simulation=False, options=options, cancel_check=cancel_check)
        duration_ms = result.duration_ms or int((time.monotonic() - started) * 1000)
        parsed = 0
        if result.status == scanner_tools.STATE_COMPLETED:
            parsed = _persist_adapter_observations(
                db, scan, tool, scan.target, result.observations)
        status = _adapter_terminal(result.status)
        _finish_execution(
            db, ex,
            status=status["execution"],
            duration_ms=duration_ms,
            parsed_observations=parsed,
            command_redacted=result.command or [tool],
            exit_code=result.exit_code,
            error_code=status["code"],
            termination_reason=result.error,
        )
        last = (result, parsed, duration_ms, status)
        event_status = status["event"]
        if event_status == "timed_out":
            event_status = "timeout"
        events.emit_tool(db, scan.id, tool, event_status, attempt=attempts,
                         stage=TOOL_TO_STAGE.get(tool),
                         detail={"parsed_observations": parsed,
                                 "duration_ms": duration_ms})
        if status["execution"] not in ("timeout", "failed"):
            break

    result, parsed, duration_ms, status = last
    log = result.raw_output or f"[{tool}] {status['execution']}"
    legacy = {
        "tool": tool,
        "status": _adapter_legacy_status(status["execution"]),
        "log": clip(log),
        "error": result.error,
    }
    _save_result(db, scan.id, tool, legacy)
    return {"tool": tool, "status": legacy["status"],
            "observations": result.observations, "log": legacy["log"],
            "parsed": parsed, "duration_ms": duration_ms}


def _adapter_default_options(tool: str) -> dict:
    if tool == "nmap":
        return {"ports": "80,443,22,3000,3306,5432,8080,8443"}
    return {}


def _adapter_terminal(status: str) -> dict:
    if status == scanner_tools.STATE_COMPLETED:
        return {"execution": "completed", "event": "completed", "code": None}
    if status == scanner_tools.STATE_NOT_INSTALLED:
        return {"execution": "not_installed", "event": "not_installed", "code": "not_installed"}
    if status == scanner_tools.STATE_TIMEOUT:
        return {"execution": "timeout", "event": "timed_out", "code": "timeout"}
    if status == scanner_tools.STATE_PARSE_FAILED:
        return {"execution": "parse_failed", "event": "parse_failed", "code": "parse_failed"}
    return {"execution": "failed", "event": "failed", "code": "execution_failed"}


def _adapter_legacy_status(execution: str) -> str:
    return {
        "completed": "success",
        "not_installed": scanner_tools.STATE_NOT_INSTALLED,
        "timeout": scanner_tools.STATE_TIMEOUT,
        "parse_failed": scanner_tools.STATE_PARSE_FAILED,
    }.get(execution, scanner_tools.STATE_EXECUTION_FAILED)


__all__ = ["execute_tool", "clip"]