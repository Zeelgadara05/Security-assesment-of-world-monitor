"""TLS configuration analysis (Phase 5).

Native and read-only: inspects the presented certificate and negotiated
protocol.  Requires no external ``testssl`` binary; if the TLS probe cannot
complete it records nothing rather than guessing.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from app.assess.models import AssessmentContext, CandidateData, ObservationData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm
from app.http.fingerprints import fetch_tls_info
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


class TlsTest(BaseSecurityTest):
    id = "tls.configuration"
    name = "Weak TLS configuration"
    category = "tls"
    description = "The TLS certificate or negotiated protocol is weak or invalid."
    active = False
    required_observations = ()  # TLS info is fetched natively

    def is_applicable(self, context: AssessmentContext) -> tuple[bool, str]:
        applicable, reason = super().is_applicable(context)
        if not applicable:
            return False, reason
        has_https = any(e.lower().startswith("https://") for e in context.endpoints)
        if not has_https and not context.has_observation(types.OBS_CERTIFICATE):
            return False, "no HTTPS endpoint or certificate observation"
        return True, ""

    def plan(self, context: AssessmentContext):
        return []

    def run(self, context: AssessmentContext) -> TestOutcome:
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        seen_hosts: set[str] = set()
        for endpoint in context.endpoints:
            parts = urlsplit(endpoint)
            if parts.scheme.lower() != "https":
                continue
            host = parts.hostname or ""
            if not host or host in seen_hosts:
                continue
            seen_hosts.add(host)
            info = fetch_tls_info(endpoint, timeout=context.limits.request_timeout)
            if not info:
                outcome.skipped += 1
                continue
            outcome.executed += 1
            outcome.observations.append(ObservationData(
                observation_type=types.OBS_CERTIFICATE, subject=host, data=info,
                tool_name="native_tls", source=types.SOURCE_STDLIB_PROBE,
                discriminator={"host": host, "test": self.id},
            ))
            if info.get("expired"):
                outcome.candidates.append(self._candidate(
                    endpoint, "Expired TLS certificate", types.SEVERITY_MEDIUM,
                    "transport identity", "certificate within validity window",
                    f"expired at {info.get('not_after')}"))
            protocol = (info.get("protocol") or "").upper()
            if protocol in {p.upper() for p in _WEAK_PROTOCOLS}:
                outcome.candidates.append(self._candidate(
                    endpoint, f"Weak TLS protocol negotiated ({protocol})", types.SEVERITY_MEDIUM,
                    "transport confidentiality", "TLS 1.2 or newer",
                    f"negotiated {protocol}"))
        return outcome

    def _candidate(self, endpoint, title, severity, boundary, expected, actual) -> CandidateData:
        result = confirm(f"{title} at {endpoint}", confidence=types.CONFIDENCE_HIGH,
                         expected=expected, actual=actual, boundary=boundary)
        return CandidateData(
            category=self.category, title=title, severity=severity, confidence=result.confidence,
            description=self.description, endpoint=endpoint, method="GET", target=endpoint,
            source_test=self.id, source_tool="native_tls", security_boundary=boundary,
            expected=expected, actual=actual,
            impact="Communication security cannot be relied upon.",
            proof_of_concept=f"TLS probe {endpoint}",
            dedup_key=finding_fingerprint(self.category, endpoint, endpoint, title),
        )


TEST = TlsTest()
