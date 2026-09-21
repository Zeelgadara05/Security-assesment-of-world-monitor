"""Phase 8.5 SIH26163 security-area mapping and derived coverage."""
from __future__ import annotations

from app.assess.sih import (
    CATEGORY_TO_AREAS,
    SIH_AREAS,
    areas_for_category,
    coverage_by_area,
)


def test_seven_sih_areas_defined():
    assert list(SIH_AREAS.keys()) == [
        "authentication",
        "authorization",
        "input_validation",
        "api_security",
        "client_side",
        "secure_communication",
        "data_protection",
    ]


def test_areas_for_category():
    assert areas_for_category("authorization") == ("authorization",)
    assert set(areas_for_category("xss")) == {"input_validation", "client_side"}
    assert set(areas_for_category("cors")) == {"api_security", "client_side"}
    assert areas_for_category("unknown_thing") == ()
    assert areas_for_category(None) == ()


def test_coverage_reflects_ledger_only():
    tests = [
        {"category": "auth", "status": "executed"},
        {"category": "authorization", "status": "validated"},
        {"category": "authorization", "status": "planned"},
        {"category": "tls", "status": "not_applicable"},
        {"category": "weird_unmapped", "status": "executed"},
    ]
    payload = coverage_by_area(tests)
    by_key = {a["key"]: a for a in payload["areas"]}

    auth = by_key["authentication"]
    assert auth["executed"] == 1 and auth["coverage_percent"] == 100.0
    assert auth["status"] == "covered"

    access = by_key["authorization"]
    assert access["executed"] == 1 and access["applicable"] == 2
    assert access["coverage_percent"] == 50.0 and access["status"] == "partial"

    tls = by_key["secure_communication"]
    assert tls["not_applicable"] == 1 and tls["applicable"] == 0
    assert tls["coverage_percent"] is None and tls["status"] == "not_assessed"

    assert payload["unmapped_categories"] == {"weird_unmapped": 1}


def test_area_with_no_tests_is_not_assessed_not_zero():
    payload = coverage_by_area([])
    for area in payload["areas"]:
        assert area["coverage_percent"] is None
        assert area["status"] == "not_assessed"


def test_multi_area_category_counts_in_each_area():
    payload = coverage_by_area([{"category": "ssrf", "status": "executed"}])
    by_key = {a["key"]: a for a in payload["areas"]}
    assert by_key["input_validation"]["executed"] == 1
    assert by_key["api_security"]["executed"] == 1


def test_every_mapped_category_points_to_a_real_area():
    for category, areas in CATEGORY_TO_AREAS.items():
        assert areas, category
        for area in areas:
            assert area in SIH_AREAS, (category, area)
