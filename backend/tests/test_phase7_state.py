"""Phase 7 state machine unit tests.

The Phase 7 ``Scan.state`` machine is a superset of the legacy stage.  These
tests pin the constant vocabulary, the guarded transition table, terminal
immutability and the coarse-completion mapping used by API consumers.
"""

import pytest

from app.orchestration import state as SM


def test_constants_and_ordering():
    assert SM.ALL == (
        "created", "queued", "preflight", "running", "validating", "finalizing",
        "completed", "completed_with_gaps", "blocked", "failed", "cancelled",
    )
    assert SM.TERMINAL == frozenset(
        {"completed", "completed_with_gaps", "blocked", "failed", "cancelled"})
    assert set(SM.ACTIVE) == set(SM.ALL) - SM.TERMINAL


def test_terminal_helpers():
    assert SM.is_terminal(SM.COMPLETED)
    assert SM.is_terminal(SM.CANCELLED)
    assert not SM.is_terminal(SM.RUNNING)
    assert SM.is_active(SM.QUEUED)
    assert not SM.is_active(SM.FAILED)


def test_happy_path_transitions_are_valid():
    path = (SM.CREATED, SM.QUEUED, SM.PREFLIGHT, SM.RUNNING, SM.VALIDATING,
            SM.FINALIZING, SM.COMPLETED)
    for current, nxt in zip(path, path[1:]):
        assert SM.can_transition(current, nxt)
        SM.validate_transition(current, nxt)


def test_created_may_be_cancelled_directly():
    assert SM.can_transition(SM.CREATED, SM.CANCELLED)


def test_completed_with_gaps_is_reachable_from_running_and_finalizing():
    assert SM.can_transition(SM.RUNNING, SM.COMPLETED_WITH_GAPS)
    assert SM.can_transition(SM.FINALIZING, SM.COMPLETED_WITH_GAPS)


def test_illegal_transitions_raise():
    for current, nxt in [
        (SM.RUNNING, SM.COMPLETED),          # must go through validating
        (SM.CREATED, SM.PREFLIGHT),          # must go through queued
        (SM.QUEUED, SM.VALIDATING),          # cannot skip preflight
        (SM.VALIDATING, SM.COMPLETED),       # must go through finalizing
        (SM.PREFLIGHT, SM.PREFLIGHT),        # no self loops
    ]:
        with pytest.raises(ValueError):
            SM.validate_transition(current, nxt)
        assert not SM.can_transition(current, nxt)


def test_terminal_states_are_immutable():
    for terminal in SM.TERMINAL:
        assert SM.can_transition(terminal, SM.COMPLETED) is False
        with pytest.raises(ValueError):
            SM.validate_transition(terminal, SM.COMPLETED)


def test_unknown_state_raises():
    with pytest.raises(ValueError):
        SM.validate_transition("nonsense", SM.COMPLETED)
    with pytest.raises(ValueError):
        SM.validate_transition(SM.CREATED, "nonsense")


def test_coarse_completion_mapping():
    assert SM.coarse_completion(SM.COMPLETED) == "Completed"
    assert SM.coarse_completion(SM.COMPLETED_WITH_GAPS) == "Partially Completed"
    assert SM.coarse_completion(SM.BLOCKED) == "Blocked"
    assert SM.coarse_completion(SM.FAILED) == "Failed"
    assert SM.coarse_completion(SM.CANCELLED) == "Cancelled"
    assert SM.coarse_completion(SM.RUNNING) == "Running"


def test_terminal_order_is_stable():
    assert SM.TERMINAL_ORDER == ("completed", "completed_with_gaps", "blocked",
                                 "failed", "cancelled")