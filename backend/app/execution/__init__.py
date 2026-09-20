"""Real process execution primitives (Phase 7).

``BoundedRunner`` is the single place a Phase 7 scan ever starts an external
process: it enforces a hard timeout, an output-size bound (bounded memory,
documented truncation), and cooperative cancellation so the operator request
to abort a scan actually terminates the running binary.
"""
from app.execution.runner import BoundedRunner, RunTelemetry

__all__ = ["BoundedRunner", "RunTelemetry"]