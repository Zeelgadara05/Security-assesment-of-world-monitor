"""World Monitor → observation normalization (Phase 8).

Everything discovered through World Monitor enters the existing observation
system via ``app.observations.normalize.build_observation`` -- the same single
choke point (normalization **and** redaction) every other source uses.  No
second observation format exists.

Provenance per the phase requirements is preserved inside ``data_json``:

    source = "world_monitor"      (marker)
    source_type = api_discovery | health_check
    target_id, endpoint, method, observation_time
"""
from __future__ import annotations

import datetime

from app.integrations.world_monitor.models import APIEndpoint, HealthResult
from app.observations import types as obs_types
from app.observations.normalize import build_observation

_OBSERVATION_SOURCE = obs_types.SOURCE_HTTP_CLIENT


def _wm_provenance(target_id: int, source_type: str) -> dict:
    return {
        "source": "world_monitor",
        "source_type": source_type,
        "target_id": target_id,
        "observation_time": datetime.datetime.utcnow().isoformat(),
    }


def health_observations(
    *,
    scan_id: int,
    target_id: int,
    subject: str,
    tool_name: str,
    health: HealthResult,
    user_id: str | None = None,
) -> list[dict]:
    """Normalize a health result through ``build_observation``.

    Returns one ``http_response`` observation (or an ``http_error`` row when
    the probe could not complete) and, when TLS metadata was captured, one
    ``certificate`` observation.
    """
    if health.reachable:
        observations = [build_observation(
            scan_id=scan_id,
            observation_type=obs_types.OBS_HTTP_RESPONSE,
            subject=subject,
            tool_name=tool_name,
            source=_OBSERVATION_SOURCE,
            user_id=user_id,
            data={
                "url": health.url,
                "status_code": health.http_status,
                "reachable": True,
                "server": health.server or "",
                "version_hint": health.version_hint,
                "detected_metadata": health.detected_metadata,
                "tls": health.tls,
                "elapsed_ms": round(health.elapsed_ms, 2),
                **_wm_provenance(target_id, "health_check"),
            },
            raw_output=(
                f"GET {health.url} -> HTTP {health.http_status} "
                f"({health.elapsed_ms:.1f} ms"
                + (f", server={health.server}" if health.server else "")
                + ")"
            ),
            status=obs_types.STATUS_OBSERVED,
            discriminator={"url": health.url, "type": "health_check"},
        )]
    else:
        observations = [build_observation(
            scan_id=scan_id,
            observation_type=obs_types.OBS_ERROR,
            subject=subject,
            tool_name=tool_name,
            source=_OBSERVATION_SOURCE,
            user_id=user_id,
            data={
                "url": health.url,
                "reachable": False,
                "http_status": health.http_status,
                "error": health.error or "unreachable",
                **_wm_provenance(target_id, "health_check"),
            },
            raw_output=f"GET {health.url} unreachable: {health.error or 'no response'}",
            status=obs_types.STATUS_UNREACHABLE,
            discriminator={"url": health.url, "type": "health_check"},
        )]

    if health.tls:
        tls = health.tls or {}
        observations.append(build_observation(
            scan_id=scan_id,
            observation_type=obs_types.OBS_CERTIFICATE,
            subject=subject,
            tool_name=tool_name,
            source=_OBSERVATION_SOURCE,
            user_id=user_id,
            data={
                "host": subject,
                "protocol": tls.get("protocol"),
                "cipher": tls.get("cipher"),
                "issuer": tls.get("issuer"),
                "subject_san": list(tls.get("subject_alt_names") or []),
                "not_after": tls.get("not_after"),
                "expired": tls.get("expired"),
                **_wm_provenance(target_id, "health_check"),
            },
            raw_output=(
                f"TLS {tls.get('protocol') or 'unknown'} cipher={tls.get('cipher') or 'n/a'} "
                f"issuer={tls.get('issuer') or 'n/a'}"
            ),
            status=obs_types.STATUS_OBSERVED,
            discriminator={"host": subject, "type": "tls"},
        ))

    return observations


def endpoint_observation(
    *,
    scan_id: int,
    target_id: int,
    endpoint: APIEndpoint,
    source_url: str,
    tool_name: str,
    user_id: str | None = None,
) -> dict:
    """Normalize a discovered API endpoint into an ``api_route`` observation."""
    return build_observation(
        scan_id=scan_id,
        observation_type=obs_types.OBS_API_ROUTE,
        subject=source_url,
        tool_name=tool_name,
        source=_OBSERVATION_SOURCE,
        user_id=user_id,
        data={
            "method": endpoint.method.upper(),
            "path": endpoint.path,
            "operation_id": endpoint.operation_id,
            "tags": list(endpoint.tags or []),
            "source": endpoint.source,
            "authentication_hint": endpoint.authentication_hint,
            "source_url": source_url,
            **_wm_provenance(target_id, "api_discovery"),
        },
        raw_output=f"{endpoint.method.upper()} {source_url}{endpoint.path}",
        status=obs_types.STATUS_OBSERVED,
        discriminator={
            "endpoint": source_url,
            "method": endpoint.method.upper(),
            "path": endpoint.path,
            "extra": "world_monitor",
        },
    )


__all__ = ["health_observations", "endpoint_observation"]