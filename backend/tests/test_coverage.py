"""Phase 6 assessment-summary / coverage classification tests.

Coverage describes the assessment performed -- never a security verdict.  A scan
with zero applicable tests reports ``coverage_percent=None`` and unknown
completeness; gaps produce ``completed_with_gaps``; a fully executed applicable
set produces ``completed``.  The headline must never fabricate risk.
"""
from app.assess import summary as summary_mod
from app.assess.summary import (
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_GAPS,
    STATUS_NOT_STARTED,
    classify,
    headline,
    sanitized_config,
)
from app.reporting.coverage_renderer import coverage_payload


def _full_coverage():
    return {
        "tests_applicable": 4,
        "tests_executed": 4,
        "tests_skipped": 0,
        "tests_failed": 0,
        "coverage_percent": 100.0,
    }


def test_completed_when_full_coverage_no_gaps():
    status, completeness = classify(coverage=_full_coverage())
    assert status == STATUS_COMPLETED
    assert completeness == summary_mod.COMPLETE


def test_gaps_never_claimed_complete():
    status, completeness = classify(coverage={
        "tests_applicable": 4, "tests_executed": 2, "tests_skipped": 2,
        "tests_failed": 0, "coverage_percent": 50.0,
    })
    assert status == STATUS_COMPLETED_WITH_GAPS
    assert completeness == summary_mod.PARTIAL

    status2, _ = classify(coverage=_full_coverage(), tools_missing=["nuclei"])
    assert status2 == STATUS_COMPLETED_WITH_GAPS


def test_no_applicable_tests_is_not_started_unknown():
    status, completeness = classify(coverage=None)
    assert status == STATUS_NOT_STARTED
    assert completeness == summary_mod.UNKNOWN


def test_all_skipped_is_minimal_coverage():
    status, completeness = classify(coverage={
        "tests_applicable": 3, "tests_executed": 0, "tests_skipped": 3,
        "tests_failed": 0, "coverage_percent": 0.0,
    })
    assert status == STATUS_COMPLETED_WITH_GAPS
    assert completeness == summary_mod.MINIMAL


def test_headline_never_says_zero_vulnerabilities():
    s = headline(aggregate_counts={"total_confirmed": 0}, coverage=_full_coverage(),
                 status=STATUS_COMPLETED)
    assert "0 confirmed findings" in s
    assert "0 vulnerabilities" not in s
    s_unknown = headline(coverage=None)
    assert "coverage unknown" in s_unknown


def test_headline_includes_coverage_and_gap_flag():
    s = headline(aggregate_counts={"total_confirmed": 1}, coverage={
        "tests_applicable": 4, "tests_executed": 2, "tests_skipped": 2,
        "tests_failed": 0, "coverage_percent": 50.0,
    }, status=STATUS_COMPLETED_WITH_GAPS)
    assert "1 confirmed finding" in s
    assert "50.0%" in s
    assert "incomplete" in s


def test_sanitized_config_never_exposes_secrets():
    safe = sanitized_config({
        "auth_identities": {"alice": {"headers": {"Authorization": "Bearer tok"}}},
        "jwt_tokens": ["eyJ.eyJ.sig"],
        "ssrf_token": "super-secret-callback-token",
        "ssrf_validation_url": "https://callbacks.local/v",
        "active_testing": True,
        "installed_tools": ["nmap"],
    })
    assert safe["auth_identities_configured"] is True
    assert safe["auth_identities_labels"] == ["alice"]
    assert safe["jwt_tokens_configured"] is True
    assert safe["ssrf_token_configured"] is True
    serialized = str(safe)
    assert "Bearer" not in serialized
    assert "eyJ" not in serialized
    assert "super-secret" not in serialized


def test_coverage_payload_is_honest_when_missing():
    payload = coverage_payload(None)
    assert payload["coverage_percent"] is None
    assert payload["tests_applicable"] == 0
    assert "vulnerabilities" not in payload