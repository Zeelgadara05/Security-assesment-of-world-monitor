"""Auditable registry of Phase 5 security tests.

The registry is an explicit, ordered catalogue.  It exposes lookup by id and by
category and a stable fingerprint so the exact set of executed tests can be
recorded with a scan -- coverage claims are meaningless if the catalogue is not
pinned.
"""
from __future__ import annotations

import hashlib

from app.assess.tests import ALL_TESTS, get_all_tests


class TestRegistry:
    def __init__(self, tests=None) -> None:
        self._tests = list(tests if tests is not None else get_all_tests())
        self._by_id = {test.id: test for test in self._tests}

    # -- access --------------------------------------------------------------
    def all(self) -> list:
        return list(self._tests)

    def get(self, test_id: str):
        return self._by_id.get(test_id)

    def ids(self) -> list[str]:
        return [test.id for test in self._tests]

    def categories(self) -> list[str]:
        seen: list[str] = []
        for test in self._tests:
            if test.category not in seen:
                seen.append(test.category)
        return seen

    def by_category(self, category: str) -> list:
        return [test for test in self._tests if test.category == category]

    def active_tests(self) -> list:
        return [test for test in self._tests if test.active]

    def passive_tests(self) -> list:
        return [test for test in self._tests if not test.active]

    def add(self, test) -> None:
        if test.id in self._by_id:
            raise ValueError(f"duplicate security test id: {test.id}")
        self._tests.append(test)
        self._by_id[test.id] = test

    # -- audit ---------------------------------------------------------------
    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for test_id in sorted(self._by_id):
            digest.update(test_id.encode("utf-8"))
            digest.update(b"\x00")
        return digest.hexdigest()[:16]

    def describe(self) -> list[dict]:
        return [
            {
                "id": test.id,
                "name": test.name,
                "category": test.category,
                "active": bool(test.active),
                "destructive": bool(getattr(test, "destructive", False)),
                "authentication_required": bool(getattr(test, "authentication_required", False)),
                "required_observations": list(getattr(test, "required_observations", ())),
                "required_capabilities": list(getattr(test, "required_capabilities", ())),
            }
            for test in self._tests
        ]


def default_registry() -> TestRegistry:
    return TestRegistry(ALL_TESTS)


__all__ = ["TestRegistry", "default_registry"]
