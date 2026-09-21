"""SIH26163 security-area mapping (Phase 8.5).

Maps the engine's rule-level assessment categories (``auth``, ``authorization``,
``sqli``, ``tls``, ...) onto the seven security areas the SIH problem statement
calls out, and derives per-area coverage from the *persisted assessment-test
ledger* only.  Coverage describes which tests were executed for an area -- it is
never a security score, and an area with no applicable tests is reported as
``not_assessed`` rather than a fabricated percentage.

The mapping is intentionally explicit and reviewable.  A category may belong to
more than one area (e.g. ``cors`` is both an API and a client-side concern); the
same test then contributes to each area it genuinely exercises.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Any, Iterable

# --- the seven SIH26163 security areas -------------------------------------
SIH_AREAS: "OrderedDict[str, dict[str, str]]" = OrderedDict([
    ("authentication", {
        "title": "Authentication & Session Management",
        "description": "Credential handling, session cookies, tokens and login/logout controls.",
    }),
    ("authorization", {
        "title": "Authorization & Access Control",
        "description": "Function-level and object-level access control across identities.",
    }),
    ("input_validation", {
        "title": "Input Validation & Data Handling",
        "description": "Injection, unsafe input handling and server-side request forgery.",
    }),
    ("api_security", {
        "title": "API Security",
        "description": "API surface, method exposure, CORS and GraphQL behaviour.",
    }),
    ("client_side", {
        "title": "Client-Side Security",
        "description": "Browser-facing weaknesses and security response headers.",
    }),
    ("secure_communication", {
        "title": "Secure Communication (TLS)",
        "description": "Transport encryption, certificate validity and HSTS.",
    }),
    ("data_protection", {
        "title": "Data Protection & Privacy",
        "description": "Sensitive-data exposure, disclosure and privacy-relevant leaks.",
    }),
])

# --- rule-level category -> SIH areas --------------------------------------
CATEGORY_TO_AREAS: dict[str, tuple[str, ...]] = {
    # Authentication & session management
    "auth": ("authentication",),
    "authentication": ("authentication",),
    "session": ("authentication",),
    "cookies": ("authentication",),
    "jwt": ("authentication",),
    "oauth": ("authentication",),
    "csrf": ("authentication", "client_side"),
    # Authorization & access control
    "authorization": ("authorization",),
    "idor": ("authorization",),
    "bola": ("authorization",),
    "access_control": ("authorization",),
    # Input validation & data handling
    "sqli": ("input_validation",),
    "ssti": ("input_validation",),
    "xss": ("input_validation", "client_side"),
    "redirects": ("input_validation",),
    "injection": ("input_validation",),
    "command_injection": ("input_validation",),
    "xxe": ("input_validation",),
    "ssrf": ("input_validation", "api_security"),
    # API security
    "api_security": ("api_security",),
    "graphql": ("api_security",),
    "methods": ("api_security",),
    "cors": ("api_security", "client_side"),
    # Client-side / secure communication
    "headers": ("client_side", "secure_communication"),
    "tls": ("secure_communication",),
    # Data protection & privacy
    "disclosure": ("data_protection",),
    "privacy": ("data_protection",),
    "data_protection": ("data_protection",),
}

_EXECUTED_STATUSES = {"executed", "validated", "rejected"}
_APPLICABLE_EXCLUDED = {"not_applicable"}


def areas_for_category(category: str | None) -> tuple[str, ...]:
    """SIH area keys exercised by a rule-level category (empty when unmapped)."""
    if not category:
        return ()
    return CATEGORY_TO_AREAS.get(category.strip().lower(), ())


def coverage_by_area(tests: Iterable[dict]) -> dict[str, Any]:
    """Derive per-area coverage from persisted assessment-test rows.

    ``tests`` is the ledger as returned by the scan detail endpoint (dicts with
    ``category`` and ``status``).  Every count is a real tally of ledger rows;
    when an area has no applicable tests its coverage is ``None`` and its label
    is ``not_assessed`` (never ``0%`` masquerading as a result).
    """
    counts: dict[str, dict[str, int]] = {
        key: {"total": 0, "executed": 0, "planned": 0, "skipped": 0,
              "failed": 0, "not_applicable": 0}
        for key in SIH_AREAS
    }
    unmapped: dict[str, int] = {}

    for test in tests or []:
        category = (test.get("category") or "").strip().lower()
        areas = CATEGORY_TO_AREAS.get(category)
        if not areas:
            if category:
                unmapped[category] = unmapped.get(category, 0) + 1
            continue
        status = (test.get("status") or "planned").strip().lower()
        for area in areas:
            bucket = counts[area]
            bucket["total"] += 1
            if status in _EXECUTED_STATUSES:
                bucket["executed"] += 1
            elif status == "not_applicable":
                bucket["not_applicable"] += 1
            elif status == "skipped":
                bucket["skipped"] += 1
            elif status == "failed":
                bucket["failed"] += 1
            else:  # planned or any future/unknown non-executed state
                bucket["planned"] += 1

    areas: list[dict[str, Any]] = []
    for key, meta in SIH_AREAS.items():
        bucket = counts[key]
        applicable = (bucket["total"] - bucket["not_applicable"])
        if applicable <= 0:
            percent = None
            label = "not_assessed"
        else:
            percent = round(bucket["executed"] / applicable * 100, 1)
            if bucket["executed"] == 0:
                label = "not_assessed"
            elif bucket["executed"] >= applicable:
                label = "covered"
            else:
                label = "partial"
        areas.append({
            "key": key,
            "title": meta["title"],
            "description": meta["description"],
            "total": bucket["total"],
            "applicable": applicable,
            "executed": bucket["executed"],
            "planned": bucket["planned"],
            "skipped": bucket["skipped"],
            "failed": bucket["failed"],
            "not_applicable": bucket["not_applicable"],
            "coverage_percent": percent,
            "status": label,
            "categories": sorted({c for c, a in CATEGORY_TO_AREAS.items() if key in a}),
        })

    return {
        "framework": "SIH26163",
        "areas": areas,
        "unmapped_categories": dict(sorted(unmapped.items())),
    }


__all__ = [
    "SIH_AREAS",
    "CATEGORY_TO_AREAS",
    "areas_for_category",
    "coverage_by_area",
]
