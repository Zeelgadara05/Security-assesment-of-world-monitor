"""Information-disclosure analysis (Phase 5).

Passive: scans already-observed response bodies for concrete disclosure
signatures and assigns severity from *what was actually exposed* -- a framework
name alone is not equivalent to a leaked credential.
"""
from __future__ import annotations

import re

from app.assess.models import AssessmentContext, CandidateData, TestOutcome
from app.assess.tests.base import BaseSecurityTest
from app.assess.tests.util import observation_body, observation_url
from app.assess.validators import confirm
from app.observations import types
from app.observations.fingerprint import finding_fingerprint

_SIGNATURES = [
    # (id, regex, title, severity, boundary, data_exposure)
    ("stack-trace", re.compile(r"Traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)|Stack trace:", re.I),
     "Application stack trace exposed", types.SEVERITY_MEDIUM, "implementation detail", False),
    ("framework-debug", re.compile(r"Whitelabel Error Page|Werkzeug Debugger|DEBUG = True|laravel.*whoops|django\.core\.exceptions", re.I),
     "Framework debug page exposed", types.SEVERITY_MEDIUM, "implementation detail", False),
    ("internal-path", re.compile(r"(?:/home/[\w.-]+/|/var/www/|C:\\\\inetpub\\\\|/usr/src/app/)"),
     "Internal filesystem path disclosed", types.SEVERITY_LOW, "environment detail", False),
    ("source-map", re.compile(r"//[#@]\s*sourceMappingURL="),
     "JavaScript source map reference exposed", types.SEVERITY_LOW, "source disclosure", False),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "Private key material disclosed in response", types.SEVERITY_CRITICAL, "credential exposure", True),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "Potential AWS access key disclosed", types.SEVERITY_HIGH, "credential exposure", True),
    ("secret-assignment", re.compile(r"(?:DB_PASSWORD|SECRET_KEY|AWS_SECRET_ACCESS_KEY|API_SECRET)\s*[:=]\s*\S+", re.I),
     "Secret-like configuration value disclosed", types.SEVERITY_HIGH, "credential exposure", True),
    ("db-error", re.compile(r"SQLSTATE\[|ORA-\d{5}|You have an error in your SQL syntax|sqlite3\.OperationalError", re.I),
     "Database error message disclosed", types.SEVERITY_MEDIUM, "implementation detail", False),
]


class DisclosureTest(BaseSecurityTest):
    id = "http.information_disclosure"
    name = "Information disclosure in responses"
    category = "disclosure"
    description = "Response bodies disclose stack traces, paths, secrets or database errors."
    required_observations = (types.OBS_HTTP_RESPONSE,)
    active = False

    def run(self, context: AssessmentContext) -> TestOutcome:
        applicable, reason = self.is_applicable(context)
        if not applicable:
            return TestOutcome(test_id=self.id, category=self.category,
                               status=types.TEST_NOT_APPLICABLE, reason=reason)
        outcome = TestOutcome(test_id=self.id, category=self.category, status=types.TEST_EXECUTED)
        seen: set[str] = set()
        for obs in context.observations_of(types.OBS_HTTP_RESPONSE, types.OBS_TOOL_OUTPUT):
            url = observation_url(obs)
            body = observation_body(obs)
            if not body:
                continue
            outcome.executed += 1
            for sig_id, pattern, title, severity, boundary, data_exposure in _SIGNATURES:
                match = pattern.search(body)
                if not match:
                    continue
                key = finding_fingerprint(self.category, url, url, sig_id)
                if key in seen:
                    continue
                seen.add(key)
                snippet = match.group(0)[:200]
                result = confirm(f"{title}: matched {sig_id}", confidence=types.CONFIDENCE_HIGH,
                                 expected="no sensitive detail in response", actual=snippet,
                                 boundary=boundary)
                outcome.candidates.append(CandidateData(
                    category=self.category, title=title, severity=severity,
                    confidence=result.confidence, description=self.description,
                    endpoint=url, method="GET", target=url, source_test=self.id,
                    source_tool="native_http", security_boundary=boundary,
                    expected="no sensitive detail in response", actual=snippet,
                    impact=f"{'Credential' if data_exposure else 'Implementation'} detail disclosed: {snippet[:120]}",
                    proof_of_concept=f"GET {url}",
                    observation_ids=[obs.get("id")] if obs.get("id") else [],
                    dedup_key=key,
                ))
        return outcome


TEST = DisclosureTest()
