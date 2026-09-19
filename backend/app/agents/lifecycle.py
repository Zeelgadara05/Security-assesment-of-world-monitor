"""Scan job lifecycle (Phase 4).

A scan is a *job* that advances through a fixed sequence of stages.  Each stage
persists as ``Scan.stage``; the coarse ``Scan.status`` (Pending/Running/
Completed/Failed/Cancelled) is derived so existing consumers keep working while
the detailed lifecycle is tracked and streamed.

Progress is *real*: counters only move when a stage/tool actually completes.
``coverage`` is the percentage of planned tasks that actually executed to a
successful state - it is a separate concept from the risk ``security_score``.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Lifecycle stages (the fine-grained job state machine)
# ---------------------------------------------------------------------------
QUEUED = "queued"
STARTING = "starting"
RECON = "recon"
DISCOVERY = "discovery"
SERVICE_SCAN = "service_scan"
HTTP_SCAN = "http_scan"
VULNERABILITY_SCAN = "vulnerability_scan"
ANALYSIS = "analysis"
REPORTING = "reporting"
COMPLETED = "completed"
PARTIAL = "partial"
FAILED = "failed"
CANCELLED = "cancelled"

STAGES = [
    QUEUED, STARTING, RECON, DISCOVERY, SERVICE_SCAN, HTTP_SCAN,
    VULNERABILITY_SCAN, ANALYSIS, REPORTING,
]

TERMINAL_STAGES = {COMPLETED, PARTIAL, FAILED, CANCELLED}


def is_terminal(stage: str) -> bool:
    return (stage or "").lower() in TERMINAL_STAGES


# ---------------------------------------------------------------------------
# Coarse status derivation (kept compatible with the pre-Phase-4 API)
# ---------------------------------------------------------------------------
def coarse_status(stage: str) -> str:
    stage = (stage or QUEUED).lower()
    if stage == QUEUED:
        return "Pending"
    if stage in TERMINAL_STAGES:
        return {
            COMPLETED: "Completed",
            PARTIAL: "Partially Completed",
            FAILED: "Failed",
            CANCELLED: "Cancelled",
        }[stage]
    return "Running"


# ---------------------------------------------------------------------------
# Progress counters (all incrementing, none fabricated)
# ---------------------------------------------------------------------------
def empty_progress() -> dict:
    return {
        "completed_tasks": 0,
        "failed_tasks": 0,
        "total_tasks": 0,
        "completed_tools": 0,
        "total_tools": 0,
        "current_tool": None,
        "current_stage_tasks": 0,
        "completed_stage_tasks": 0,
        "percent": 0,
    }


def compute_coverage(progress: dict) -> float | None:
    """Coverage = ratio of planned tasks that actually ran to success.

    Returns None when there is nothing to measure (no planned tasks yet).
    NOT_INSTALLED tools never count toward the numerator, so a truncated tool
    set honestly lowers the assessment coverage.
    """
    total = (progress or {}).get("total_tasks") or 0
    if total <= 0:
        return None
    completed = (progress or {}).get("completed_tasks") or 0
    return round(100.0 * min(completed, total) / total, 2)