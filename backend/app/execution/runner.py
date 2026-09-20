"""Bounded, cancellable external process execution.

Phase 7 scans run real binaries.  Three guarantees are enforced in this one
place and must not be bypassed:

  * bounded memory -- each stream (stdout/stderr) is captured up to a hard cap;
    once the cap is exceeded the pipe is still drained (so the child never
    blocks) but the remainder is discarded and ``*_truncated`` is set.  A
    truncated stream is honest output with an explicit flag, never a lie.
  * hard timeout   -- a run may not exceed its budget; on expiry the process is
    terminated (kill escalated) and ``timed_out`` is set.
  * cancellation   -- ``cancel_check`` is polled for the life of the run; when
    it returns True the process is terminated and ``cancelled`` is set, so an
    operator can abort a long scan and the pipeline abandons cleanly.

``RunTelemetry`` carries the outcome; callers decide what "success" means (some
tools exit non-zero but emit valid, parseable output).
"""
from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Callable, Sequence

# Per-stream capture cap.  Anything beyond this is sunk, not stored, so a
# chatty tool (whatweb, nuclei -json) cannot exhaust memory.  512 KiB per
# stream keeps every legitimate report we expect and bounds the rest.
_STREAM_CAP = 512 * 1024
_POLL_SECONDS = 0.05


@dataclass
class RunTelemetry:
    """Telemetry for one process invocation."""

    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_size: int = 0
    stderr_size: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    duration_ms: int = 0
    timed_out: bool = False
    cancelled: bool = False
    started: bool = False
    error: str | None = None
    termination_reason: str | None = None

    @property
    def terminated(self) -> bool:
        return self.timed_out or self.cancelled or self.termination_reason is not None


class _StreamReader(threading.Thread):
    """Writes lines from a pipe into a bounded buffer, sinking the overflow."""

    def __init__(self, stream, cap: int) -> None:
        super().__init__(daemon=True)
        self._stream = stream
        self._cap = cap
        self._parts: list[str] = []
        self._size = 0
        self._truncated = False
        self._closed = False

    def run(self) -> None:
        cap = self._cap
        for line in self._stream:
            if self._closed:
                continue
            encoded = line.encode("utf-8", errors="replace")
            if self._size + len(encoded) > cap:
                self._truncated = True
                continue  # sink the overflow, never store it
            self._parts.append(line)
            self._size += len(encoded)

    def close(self) -> None:
        self._closed = True
        try:
            self._stream.close()
        except Exception:  # pragma: no cover - defensive
            pass

    def result(self) -> tuple[str, int, bool]:
        return "".join(self._parts), self._size, self._truncated


def _terminate(proc: subprocess.Popen) -> None:
    proc.terminate()
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(0.05)
    try:
        proc.kill()  # escalate; the process must not survive an abort
    except Exception:  # pragma: no cover - already dead
        pass


class BoundedRunner:
    """External process runner with timeout, caps and cancellation."""

    def __init__(self, *, stream_cap: int = _STREAM_CAP,
                 poll_seconds: float = _POLL_SECONDS) -> None:
        self.stream_cap = stream_cap
        self.poll_seconds = poll_seconds

    def run(self, command: Sequence[str], *, timeout: float,
            cancel_check: Callable[[], bool] | None = None,
            env: dict | None = None, cwd: str | None = None) -> RunTelemetry:
        started = time.monotonic()
        telemetry = RunTelemetry()
        command = [str(c) for c in (command or [])]
        if not command:
            telemetry.error = "empty command"
            return telemetry

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                env=env,
                cwd=cwd,
            )
        except FileNotFoundError:
            telemetry.error = "executable not found"
            return telemetry
        except OSError as exc:  # pragma: no cover - environment specific
            telemetry.error = str(exc)
            return telemetry

        telemetry.started = True
        out = _StreamReader(proc.stdout, self.stream_cap)
        err = _StreamReader(proc.stderr, self.stream_cap)
        out.start()
        err.start()

        deadline = started + timeout
        while proc.poll() is None:
            if cancel_check is not None and cancel_check():
                telemetry.cancelled = True
                telemetry.termination_reason = "process terminated after cancellation request"
                _terminate(proc)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                telemetry.timed_out = True
                telemetry.termination_reason = f"process exceeded {timeout}s budget"
                _terminate(proc)
                break
            time.sleep(min(self.poll_seconds, max(0.0, remaining)))

        # Reap and drain.  The readers finish at EOF once the process is gone.
        try:
            proc.wait(timeout=3.0)
        except Exception:  # pragma: no cover - defensive
            _terminate(proc)
        out.join(timeout=3.0)
        err.join(timeout=3.0)
        out.close()
        err.close()

        telemetry.duration_ms = int((time.monotonic() - started) * 1000)
        telemetry.exit_code = proc.returncode
        out_text, out_size, out_trunc = out.result()
        err_text, err_size, err_trunc = err.result()
        telemetry.stdout = out_text
        telemetry.stderr = err_text
        telemetry.stdout_size = out_size
        telemetry.stderr_size = err_size
        telemetry.stdout_truncated = out_trunc
        telemetry.stderr_truncated = err_trunc or (len(err_text) >= self.stream_cap)
        return telemetry