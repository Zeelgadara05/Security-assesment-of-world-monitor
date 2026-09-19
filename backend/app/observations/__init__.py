"""Phase 5 observation layer: normalized, redacted, fingerprinted facts."""
from app.observations import types
from app.observations.fingerprint import finding_fingerprint, observation_fingerprint
from app.observations.normalize import (
    REDACTED,
    build_observation,
    normalize_endpoint,
    observation_discriminator,
    redact_headers,
    redact_mapping,
    redact_text,
)

__all__ = [
    "types",
    "observation_fingerprint",
    "finding_fingerprint",
    "build_observation",
    "normalize_endpoint",
    "observation_discriminator",
    "redact_headers",
    "redact_mapping",
    "redact_text",
    "REDACTED",
]
