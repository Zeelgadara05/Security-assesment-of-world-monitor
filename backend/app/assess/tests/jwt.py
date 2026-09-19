"""JWT configuration analysis (Phase 5).

Structural, non-forging analysis of tokens observed during the scan.  A token
using ``alg: none`` is only confirmed when the engine is told (via
``metadata['jwt_alg_none_accepted']``) that the server actually accepted it;
otherwise it is not reported as a vulnerability.  Missing expiry is a Low
finding because it is a measurable property of the token itself.
"""
from __future__ import annotations

import base64
import json

from app.assess.models import AssessmentContext, CandidateData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.validators import confirm
from app.observations import types
from app.observations.fingerprint import finding_fingerprint


class JwtTest(BaseSecurityTest):
    id = "auth.jwt"
    name = "Weak JWT configuration"
    category = "jwt"
    description = "JWTs are signed with 'none' or lack an expiry claim."
    active = False

    def is_applicable(self, context: AssessmentContext) -> tuple[bool, str]:
        applicable, reason = super().is_applicable(context)
        if not applicable:
            return False, reason
        if not (context.metadata or {}).get("jwt_tokens"):
            return False, "no JWT tokens were observed"
        return True, ""

    def run(self, context: AssessmentContext) -> TestOutcome:
        tokens = (context.metadata or {}).get("jwt_tokens") or []
        if not tokens:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE,
                               reason="no JWT tokens were observed")
        accepted_none = bool((context.metadata or {}).get("jwt_alg_none_accepted"))
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        seen: set[str] = set()
        for index, token in enumerate(tokens):
            header, payload = _decode(token)
            if not header:
                continue
            outcome.executed += 1
            subject = f"jwt:{index}"
            alg = str(header.get("alg", "")).lower()
            if alg == "none" and accepted_none:
                key = finding_fingerprint(self.category, subject, subject, "alg-none")
                if key not in seen:
                    seen.add(key)
                    result = confirm("server accepted an unsigned JWT (alg=none)",
                                     confidence=types.CONFIDENCE_HIGH,
                                     expected="signature algorithm enforced",
                                     actual="alg=none accepted", boundary="authentication integrity")
                    outcome.candidates.append(self._candidate(
                        "JWT accepted with alg=none", subject, types.SEVERITY_CRITICAL, result))
            if payload and "exp" not in payload:
                key = finding_fingerprint(self.category, subject, subject, "no-exp")
                if key not in seen:
                    seen.add(key)
                    result = confirm("JWT has no expiry claim",
                                     confidence=types.CONFIDENCE_MEDIUM,
                                     expected="exp claim present", actual="exp absent",
                                     boundary="session lifetime")
                    outcome.candidates.append(self._candidate(
                        "JWT without expiry", subject, types.SEVERITY_LOW, result))
        return outcome

    def _candidate(self, title, subject, severity, result) -> CandidateData:
        return CandidateData(
            category=self.category, title=title, severity=severity, confidence=result.confidence,
            description=self.description, endpoint=subject, method="N/A", target=subject,
            source_test=self.id, source_tool="native_http", security_boundary=result.security_boundary,
            expected=result.expected, actual=result.actual,
            impact="Token integrity or lifetime cannot be trusted.",
            proof_of_concept=f"JWT inspection ({subject})",
            dedup_key=finding_fingerprint(self.category, subject, subject, title),
        )


def _decode(token: str) -> tuple[dict, dict]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}, {}
        header = json.loads(_b64(parts[0]))
        payload = json.loads(_b64(parts[1]))
        return (header if isinstance(header, dict) else {}), (payload if isinstance(payload, dict) else {})
    except Exception:
        return {}, {}


def _b64(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


TEST = JwtTest()
