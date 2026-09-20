"""Background scan job registry and worker (Phase 4).

Replaces the Phase 3 fire-and-forget ``ThreadPoolExecutor.submit`` with a small,
in-process job registry that:

  * tracks every enqueued/running scan job and its thread,
  * owns cancellation flags (safe to flip from the API thread),
  * lets the workflow poll for cancellation between stages/tools and terminate
    the currently-running subprocess when the platform allows it,
  * cleanly derandomizes ordering: jobs still run on a bounded thread pool, but
    the registry gives each job a stable identity and state.

Celery remains an *opt-in* transport: if an app ships with a reachable broker and
Celery installed, ``DeliverableScanTask`` mirrors the same orchestration entry
point under a broker-bound name.  The in-process registry is always the fallback
and always the source of truth for cancellation signals.
"""
from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger("cyberagent.worker")

# Optional Celery transport. When either the library or a broker is absent the
# in-process registry below is the authoritative path (always present).
try:
    from celery import Celery  # type: ignore
    CELERY_AVAILABLE = True
    celery_app = Celery("cyberagent", broker=__import__("os").getenv(
        "REDIS_URL", "redis://localhost:6379/0"))
except Exception:  # pragma: no cover - environment dependent
    CELERY_AVAILABLE = False
    celery_app = None


class ScanCancelled(Exception):
    """Raised by the workflow when a cancellation signal is observed.

    Used to abandon a scan between stages/tools; the orchestrator catches it
    and persists the terminal ``Cancelled`` state.
    """


# ---------------------------------------------------------------------------
# In-process job registry
# ---------------------------------------------------------------------------
_CANCEL = "cancelled"
_COMPLETED = "completed"


class ScanJob:
    """Per-scan job state visible to both the API thread and the worker thread."""

    __slots__ = ("scan_id", "_lock", "_cancelled", "_cancel_requested",
                 "_thread", "_subprocess")

    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        self._lock = threading.Lock()
        self._cancelled = False
        self._cancel_requested = False
        self._thread: threading.Thread | None = None
        self._subprocess = None

    # -- cancellation (called from the API thread) -------------------------
    def request_cancel(self) -> None:
        with self._lock:
            self._cancel_requested = True
            if self._subprocess is not None:
                try:
                    self._subprocess.terminate()
                except Exception:  # pragma: no cover - best effort
                    pass

    def is_cancelled(self) -> bool:
        with self._lock:
            return self._cancel_requested

    def mark_cancelled(self) -> None:
        with self._lock:
            self._cancelled = True

    def is_terminated_cancellation(self) -> bool:
        with self._lock:
            return self._cancelled

    # -- lifecycle ---------------------------------------------------------
    def attach_thread(self, thread: threading.Thread) -> None:
        with self._lock:
            self._thread = thread

    @property
    def thread_alive(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    # -- subprocess handle (for terminate during long tool runs) -----------
    def attach_subprocess(self, proc) -> None:
        with self._lock:
            if self._cancel_requested:
                try:
                    proc.terminate()
                except Exception:  # pragma: no cover - best effort
                    pass
            else:
                self._subprocess = proc

    def detach_subprocess(self) -> None:
        with self._lock:
            self._subprocess = None

    def cancel_check(self):
        """Pollable callback handed to adapters/loops so they can ABORT early."""
        def _check() -> bool:
            return self.is_cancelled()
        return _check


class ScanJobRegistry:
    """Thread-safe registry of live scan jobs keyed by scan id."""

    def __init__(self) -> None:
        self._jobs: dict[int, ScanJob] = {}
        self._lock = threading.Lock()

    def register(self, scan_id: int) -> ScanJob:
        with self._lock:
            job = ScanJob(scan_id)
            self._jobs[scan_id] = job
            return job

    def get(self, scan_id: int) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(scan_id)

    def unregister(self, scan_id: int) -> None:
        with self._lock:
            self._jobs.pop(scan_id, None)

    def active_ids(self) -> list[int]:
        with self._lock:
            return list(self._jobs.keys())

    def request_cancel(self, scan_id: int) -> bool:
        job = self.get(scan_id)
        if job is None:
            return False
        job.request_cancel()
        return True


registry = ScanJobRegistry()

# ---------------------------------------------------------------------------
# Thread pool + submission
# ---------------------------------------------------------------------------
executor = ThreadPoolExecutor(max_workers=5)


def trigger_background_scan(scan_id: int, simulation: bool = True, config: dict | None = None):
    """Enqueue a scan in the in-process registry and run it in the background.

    Returns immediately.  The caller receives the scan row already persisted
    with status Pending/stage queued.  Celery is attempted first when available;
    the in-process path is authoritative and always present.
    """
    from app.agents.workflow import orchestrate_scan

    job = registry.register(scan_id)
    if _submit_celery(scan_id, simulation, config):
        logger.info(f"Scan {scan_id} enqueued on Celery transport.")
        return

    logger.info(f"Scan {scan_id} enqueued on in-process worker.")
    try:
        from app.orchestration import orchestrate_scan_phase7

        if simulation:
            runner = orchestrate_scan
        else:
            # Real scans run through the Phase 7 execution platform; the legacy
            # orchestrator remains the simulation path so its tested behaviour
            # (and SSE contract) is preserved verbatim.
            runner = orchestrate_scan_phase7
        future = executor.submit(runner, scan_id, simulation=simulation, config=config)
        # Hold the future+job pairing: the job survives via registry; the
        # thread identity is captured lazily by the orchestrator.
        future.add_done_callback(lambda _f: registry.unregister(scan_id))
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(f"Failed to enqueue scan {scan_id}: {exc}")
        registry.unregister(scan_id)
        raise


def cancel_scan(scan_id: int) -> bool:
    """Request cancellation of a running/queued scan. True if a job exists."""
    return registry.request_cancel(scan_id)


def _submit_celery(scan_id: int, simulation: bool, config: dict | None) -> bool:
    """Best-effort Celery submission; never raises."""
    try:
        from app.workers.tasks import CELERY_AVAILABLE, celery_app  # noqa
        if not CELERY_AVAILABLE or celery_app is None:
            return False
        deliverables = {"scan_id": scan_id, "simulation": simulation, "config": config or {}}
        celery_app.send_task("cyberagent.run_scan_task", kwargs=deliverables)
        return True
    except Exception as exc:  # pragma: no cover - transport dependent
        logger.warning(f"Celery unavailable for scan {scan_id}: {exc}")
        return False


if __name__ == "__main__":  # pragma: no cover
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if len(sys.argv) > 2 and sys.argv[1] == "run":
        from app.config import settings
        from database.connection import SessionLocal
        from database.models import Scan

        scan_id = int(sys.argv[2])
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            simulation = settings.simulation_mode if scan else True
        finally:
            db.close()
        orchestrate(scan_id, simulation=simulation, config={})


def orchestrate(scan_id: int, simulation: bool, config: dict | None):
    """Alias used by the CLI/bootstrap path above."""
    from app.agents.workflow import orchestrate_scan
    return orchestrate_scan(scan_id, simulation=simulation, config=config)