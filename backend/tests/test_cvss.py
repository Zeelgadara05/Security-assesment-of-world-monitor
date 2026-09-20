"""Phase 6 deterministic CVSS tests.

CVSS handling must be deterministic and consistent: parseable vectors compute a
base score and severity band; malformed vectors raise; vector/score/severity
combinations that disagree raise.  No score is fabricated: no vector -> None.
"""
import pytest

from app.assess.cvss import (
    CvssError,
    CvssValidationError,
    derive,
    parse_vector,
    severity_for_score,
    validate_cvss,
)


def test_parse_vector_accepts_valid_v31():
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert metrics["AV"] == "N"
    assert metrics["S"] == "U"
    assert metrics["C"] == "H"


def test_parse_vector_rejects_malformed():
    with pytest.raises(CvssError):
        parse_vector("")
    with pytest.raises(CvssError):
        parse_vector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")  # not v3.1
    with pytest.raises(CvssError):
        parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")  # missing A
    with pytest.raises(CvssError):
        parse_vector("CVSS:3.1/AV:XX/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")  # bad value


def test_known_vector_computes_classic_score():
    # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 (well-known public value).
    result = derive("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result.score == pytest.approx(9.8, abs=0.1)
    assert result.severity == "Critical"
    assert result.version == "3.1"


def test_zero_impact_vector_is_zero():
    result = derive("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert result.score == 0.0
    assert result.severity == "Info"


def test_derive_is_deterministic():
    vector = "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:L/I:L/A:L"
    a = derive(vector)
    b = derive(vector)
    assert a == b


def test_severity_bands():
    assert severity_for_score(0.0) == "Info"
    assert severity_for_score(3.6) == "Low"
    assert severity_for_score(4.5) == "Medium"
    assert severity_for_score(6.5) == "Medium"
    assert severity_for_score(7.2) == "High"
    assert severity_for_score(8.9) == "High"
    assert severity_for_score(9.0) == "Critical"
    assert severity_for_score(9.8) == "Critical"


def test_validate_consistent_combination_passes():
    assert validate_cvss(vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                         score=9.8, severity="Critical") is not None


def test_validate_rejects_inconsistent_score_and_severity():
    with pytest.raises(CvssValidationError):
        validate_cvss(score=9.8, severity="Low")  # 9.8 cannot be Low


def test_validate_rejects_vector_mismatching_score():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    with pytest.raises(CvssValidationError):
        validate_cvss(vector=vector, score=7.5, severity="High")


def test_validate_rejects_vector_mismatching_severity():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    with pytest.raises(CvssValidationError):
        validate_cvss(vector=vector, severity="Low")


def test_validate_without_vector_returns_none():
    assert validate_cvss() is None
    assert validate_cvss(score=None, severity=None) is None