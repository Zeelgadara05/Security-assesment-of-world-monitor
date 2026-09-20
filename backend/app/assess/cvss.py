"""Deterministic CVSS v3.1 base-score handling (Phase 6).

Three properties are enforced here:

  * parse        -- vectors are parsed into canonical metric maps; malformed
                    vectors raise :class:`CvssError`.
  * compute      -- the base score is derived from the vector using the NIST
                    v3.1 formulas, never from an LLM or a scanner's claim.
  * consistency  -- vector <-> score <-> severity must agree; inconsistent
                    combinations raise :class:`CvssValidationError`.

When no vector exists the fields stay null: a CVSS score is NEVER fabricated.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from app.observations.types import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)

CVSS_VERSION = "3.1"
SEVERITY_NONE = "None"

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR = {"N": 0.85, "L": 0.62, "H": 0.27}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

_VALID_METRICS = {"AV": _AV, "AC": _AC, "PR": _PR, "UI": _UI, "S": {"U", "C"},
                  "C": _CIA, "I": _CIA, "A": _CIA}


class CvssError(ValueError):
    """A CVSS vector could not be parsed."""


class CvssValidationError(ValueError):
    """Vector/score/severity are mutually inconsistent."""


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector into {metric: value} metrics."""
    if not vector:
        raise CvssError("empty CVSS vector")
    vector = vector.strip()
    if not vector.upper().startswith("CVSS:3.1/"):
        raise CvssError("unsupported CVSS vector: must be CVSS:3.1/")
    raw = vector.split("/", 1)[1]
    metrics: dict[str, str] = {}
    for part in raw.split("/"):
        if not part or ":" not in part:
            raise CvssError(f"malformed metric segment: {part!r}")
        key, value = part.split(":", 1)
        key = key.upper()
        value = value.upper()
        allowed = _VALID_METRICS.get(key)
        if allowed is None:
            raise CvssError(f"unknown metric {key!r}")
        if value not in allowed:
            raise CvssError(f"unknown value {value!r} for metric {key}")
        metrics[key] = value
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    missing = required - set(metrics)
    if missing:
        raise CvssError(f"missing metric(s): {', '.join(sorted(missing))}")
    return metrics


def _roundup(value: float) -> float:
    """CVSS roundup: round to one decimal, rounding half away from zero."""
    return math.ceil(value * 10 - 1e-9) / 10


def cvss31_base_score(metrics: dict[str, str] | None) -> float:
    """Compute the v3.1 base score from parsed metrics (None -> 0.0)."""
    if not metrics:
        return 0.0
    iss = 1.0 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    if metrics["S"] == "C":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        scope_factor = 1.08
    else:
        impact = 6.42 * iss
        scope_factor = 1.0
    impact = max(impact, 0.0)
    if impact <= 0:
        return 0.0
    pr = _PR[metrics["PR"]]
    if metrics["S"] == "C" and metrics["PR"] != "N":
        pr = _PR[metrics["PR"]] + 0.14  # changed-scope adjustment per v3.1
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    return _roundup(min(scope_factor * (impact + exploitability), 10.0))


def severity_for_score(score: float | None) -> str:
    """Qualitative severity band for a CVSS base score."""
    if score is None or score == 0.0:
        return SEVERITY_INFO if score == 0.0 else SEVERITY_INFO
    if score < 4.0:
        return SEVERITY_LOW
    if score < 7.0:
        return SEVERITY_MEDIUM
    if score < 9.0:
        return SEVERITY_HIGH
    return SEVERITY_CRITICAL


@dataclass(frozen=True)
class CvssResult:
    version: str
    vector: str
    score: float
    severity: str


def derive(vector: str) -> CvssResult:
    """Deterministically derive score + severity from a full vector."""
    metrics = parse_vector(vector)
    score = cvss31_base_score(metrics)
    return CvssResult(CVSS_VERSION, vector, score, severity_for_score(score))


def validate_cvss(*, vector: str | None = None, score: float | None = None,
                  severity: str | None = None) -> CvssResult | None:
    """Validate vector/score/severity consistency.

    Returns the derived :class:`CvssResult` when a vector is present, ``None``
    when nothing was supplied (permitted -- no fabricated CVSS).  Raises
    :class:`CvssValidationError` on any inconsistency.
    """
    if not vector:
        if score is None:
            return None
        band = severity_for_score(score)
        if severity and band != severity.capitalize():
            raise CvssValidationError(
                f"cvss_score {score} implies severity {band}, not {severity}")
        return None

    result = derive(vector)
    if score is not None and abs(result.score - score) > 0.05:
        raise CvssValidationError(
            f"cvss_vector {vector} computes to {result.score}, not {score}")
    if severity and severity.capitalize() != result.severity:
        raise CvssValidationError(
            f"cvss_vector {vector} implies severity {result.severity}, not {severity}")
    return result


__all__ = [
    "CVSS_VERSION",
    "CvssError",
    "CvssResult",
    "CvssValidationError",
    "cvss31_base_score",
    "derive",
    "parse_vector",
    "severity_for_score",
    "validate_cvss",
]