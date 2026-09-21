"""World Monitor integration boundary (Phase 8).

Exposes the provider facade for the rest of the application.  The integration
is deliberately narrow: real, configured World Monitor deployments are health
checked, discovered (base/API/OpenAPI) and normalized into the existing
observation pipeline -- nothing is guessed, invented or faked.
"""
from __future__ import annotations

from app.integrations.world_monitor.provider import WorldMonitorProvider

__all__ = ["WorldMonitorProvider"]