"""Tests for the AttackState finite-state machine (Section 7 #1).

Covers:
- valid + invalid transitions
- ``can_transition()`` boundary cases
- ``AttackContext.transition()`` records every successful move
- the new Section 2 #5 path: ``FULL_ATTACK`` may transition to
  ``PORTAL_RUNNING`` (run-only-the-portal subset)
- ``PORTAL_RUNNING`` may go straight to ``IDLE`` (no stop sequence)
"""

import logging

import pytest

from core.models import AccessPoint, AppConfig, AttackState
from main import AttackContext


@pytest.fixture
def ctx() -> AttackContext:
    """Fresh AttackContext — never get one that already has state."""
    return AttackContext(AppConfig())


def _wire(ctx: AttackContext) -> None:
    """Make ``ctx`` reachable enough that ``transition`` calls don't crash."""
    ctx.target_ap = AccessPoint(
        ssid="TestSSID",
        bssid="AA:BB:CC:DD:EE:FF",
        channel=6,
    )


class TestCanTransitionMatrix:
    """Each ``from -> to`` pair from the plan's documented graph."""

    @pytest.mark.parametrize(
        ("start", "target", "expected"),
        [
            # IDLE is the catch-all "may exit to IDLE" state.
            (AttackState.IDLE, AttackState.IDLE, True),
            (AttackState.SCANNING, AttackState.IDLE, True),
            (AttackState.FULL_ATTACK, AttackState.IDLE, True),
            (AttackState.PORTAL_RUNNING, AttackState.IDLE, True),
            # Happy path.
            (AttackState.IDLE, AttackState.SCANNING, True),
            (AttackState.SCANNING, AttackState.SCANNED, True),
            (AttackState.SCANNED, AttackState.TARGET_SELECTED, True),
            (AttackState.TARGET_SELECTED, AttackState.DEAUTH_RUNNING, True),
            (AttackState.DEAUTH_RUNNING, AttackState.AP_RUNNING, True),
            (AttackState.AP_RUNNING, AttackState.PORTAL_RUNNING, True),
            # Section 2 #5: full-attack subset, portal-only.
            (AttackState.FULL_ATTACK, AttackState.PORTAL_RUNNING, True),
            # Backward / step-skipping paths that must be rejected.
            (AttackState.IDLE, AttackState.SCANNED, False),
            (AttackState.IDLE, AttackState.DEAUTH_RUNNING, False),
            (AttackState.SCANNED, AttackState.DEAUTH_RUNNING, False),
            (AttackState.TARGET_SELECTED, AttackState.PORTAL_RUNNING, False),
            (AttackState.PORTAL_RUNNING, AttackState.FULL_ATTACK, False),
            (AttackState.PORTAL_RUNNING, AttackState.DEAUTH_RUNNING, False),
            # AP_RUNNING can step back to DEAUTH_RUNNING (per the matrix).
            (AttackState.AP_RUNNING, AttackState.DEAUTH_RUNNING, True),
        ],
    )
    def test_can_transition(self, ctx: AttackContext, start, target, expected):
        ctx.state = start
        assert ctx.can_transition(target) is expected


class TestTransitionSideEffects:
    """``transition()`` mutates only on success and logs both outcomes."""

    def test_successful_transition_sets_state(self, ctx):
        ctx.state = AttackState.IDLE
        assert ctx.transition(AttackState.SCANNING) is True
        assert ctx.state is AttackState.SCANNING

    def test_failed_transition_leaves_state(self, ctx):
        ctx.state = AttackState.SCANNING
        # IDLE -> DEAUTH_RUNNING is invalid.
        assert ctx.transition(AttackState.DEAUTH_RUNNING) is False
        assert ctx.state is AttackState.SCANNING

    def test_full_attack_to_portal_running(self, ctx):
        """New transition added in Section 2 #5."""
        ctx.state = AttackState.FULL_ATTACK
        assert ctx.transition(AttackState.PORTAL_RUNNING) is True
        assert ctx.state is AttackState.PORTAL_RUNNING

    def test_logged_on_success(self, ctx, caplog):
        caplog.set_level(logging.INFO, logger="wimirage")
        ctx.transition(AttackState.SCANNING)
        assert any("State transition" in rec.message for rec in caplog.records)

    def test_logged_on_failure(self, ctx, caplog):
        caplog.set_level(logging.WARNING, logger="wimirage")
        ctx.transition(AttackState.DEAUTH_RUNNING)  # IDLE -> DEAUTH invalid
        assert any("Invalid state transition" in rec.message for rec in caplog.records)


class TestBoundary:
    def test_unknown_source_state_rejects_all_but_idle(self, ctx):
        """If ``self.state`` is somehow corrupted, only IDLE is allowed."""
        from enum import Enum

        class Bogus(Enum):
            ORPHAN = "orphan"

        ctx.state = Bogus.ORPHAN
        assert ctx.can_transition(Bogus.ORPHAN) is False
        assert ctx.can_transition(AttackState.SCANNING) is False
        assert ctx.can_transition(AttackState.IDLE) is True  # catch-all

    def test_round_trip_to_idle_always_safe(self, ctx):
        """The plan explicitly says ``new_state == IDLE`` is always allowed."""
        for start in list(AttackState):
            ctx.state = start
            assert ctx.can_transition(AttackState.IDLE) is True
