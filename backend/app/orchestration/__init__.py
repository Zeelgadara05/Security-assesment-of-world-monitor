"""Phase 7 orchestration: state machine, pipeline stages, preflight,
execution persistence, typed events and the stage driver that runs a real scan.

Every module here writes rows only after the real artifact it describes
happened -- the pipeline never fabricates state, progress, tool output or
findings.  Simulation scans keep running the Phase 4 legacy orchestrator; this
package is the real-execution path.
"""
from app.orchestration.pipeline import orchestrate_scan_phase7

__all__ = ["orchestrate_scan_phase7"]