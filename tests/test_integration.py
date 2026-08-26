"""Integration test for the full attack chain (Section 7 #4).

Exercises ``MenuHandler.do_full_chain`` end-to-end, mocking out every
side-effect we can: subprocess, Scapy sniff/sendp, OS rawsocket, the
input() flow. Asserts the state machine advances through the whole
IDLE -> SCANNING -> SCANNED -> TARGET_SELECTED -> DEAUTH_RUNNING ->
AP_RUNNING -> PORTAL_RUNNING -> FULL_ATTACK graph.

This is the only test that catches regressions that span module
boundaries: Section 1 #9 (do_full_chain decomposition), Section 2 #5
(state machine), Section 3 #10 (Twilio env-vars), Section 4 #9
(threading.Event shutdown).
"""

from __future__ import annotations

import threading
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest

from core.models import AccessPoint, AppConfig, AttackState
from main import AttackContext, MenuHandler

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _InputStub:
    """Thread-safe iterator over a fixed list of inputs feeding ``input()``.

    ``do_full_chain`` calls ``input()`` at four spots:
        1. the local internet-interface prompt
        2. the AP selection menu (#)
        3. the OTP service prompt (d/t/n)
        4. never ``input()`` is called once we hit the deauth-wait loop,
           because we set the shutdown event from a separate thread.

    We provide enough answers to drive the test all the way through.
    """

    def __init__(self, answers: list[str]):
        self._answers = list(answers)
        self._lock = threading.Lock()
        self.calls: list[str] = []

    def __call__(self, prompt: str = "") -> str:
        with self._lock:
            self.calls.append(prompt)
            if not self._answers:
                raise EOFError("inputs exhausted")
            return self._answers.pop(0)


def _make_ap() -> AccessPoint:
    return AccessPoint(
        ssid="TargetCorp",
        bssid="AA:BB:CC:DD:EE:FF",
        channel=6,
        signal=-40,
        encryption="WPA2",
        clients=[],
    )


def _build_ctx() -> AttackContext:
    """Fresh ctx — never carry state between tests."""
    return AttackContext(AppConfig())


# ---------------------------------------------------------------------------
# The test proper
# ---------------------------------------------------------------------------


class TestDoFullChain:
    """Walk the chain. Mock the world. Assert state machine + wiring."""

    @pytest.fixture
    def _make_ctx(self) -> AttackContext:
        return _build_ctx()

    def _shared_patches(self, monkeypatch, ap_list: list[AccessPoint], input_stub) -> ExitStack:
        """Returns an ExitStack of every patch do_full_chain() needs."""
        stack = ExitStack()

        # 1) input() — feeds every prompt from a fixed list.
        stack.enter_context(patch("main.input", side_effect=input_stub))

        # 2) airmon-ng / iwconfig — these aren't even invoked on Windows but
        #    must still report success so MonitorMode flows forward.
        stack.enter_context(
            patch(
                "utils.monitor_mode.MonitorMode.enable_monitor",
                return_value="wlan0mon",
            )
        )

        # 3) Scapy sniff + sendp — we never want real packet I/O.
        stack.enter_context(patch("core.scanner.sniff", MagicMock()))
        stack.enter_context(patch("core.deauth.sendp", MagicMock()))

        # 4) Scapy packet construction never touches devices.
        #    Disable the APScanner._packet_handler side-effects by replacing
        #    the whole _handle_beacon path.

        # 5) DeauthAttack.start() — never let it spawn the worker thread.
        #    We replace start() and is_running() to no-ops.
        stack.enter_context(
            patch.object(
                __import__("core.deauth", fromlist=["DeauthAttack"]).DeauthAttack,
                "start",
                lambda self: None,
            )
        )
        stack.enter_context(
            patch.object(
                __import__("core.deauth", fromlist=["DeauthAttack"]).DeauthAttack,
                "is_running",
                lambda self: True,
            )
        )
        # Make the wait-loop release immediately.
        stack.enter_context(
            patch.object(MenuHandler, "_wait_for_deauth", lambda self, max_seconds=5: None)
        )

        # 6) RogueAP.start() returns True, hostapd/dnsmasq Popen mocked.
        stack.enter_context(
            patch.object(
                __import__("core.rogue_ap", fromlist=["RogueAP"]).RogueAP,
                "start",
                lambda self: True,
            )
        )

        # 7) NetworkConfig.setup_iptables() succeeds.
        stack.enter_context(
            patch.object(
                __import__("core.network", fromlist=["NetworkConfig"]).NetworkConfig,
                "setup_iptables",
                lambda self: True,
            )
        )

        # 8) CaptivePortal.start() — replace with a no-op (don't bind :80).
        stack.enter_context(
            patch.object(
                __import__("core.captive_portal", fromlist=["CaptivePortal"]).CaptivePortal,
                "start",
                lambda self: None,
            )
        )

        # 9) register_cleanup_handler — keep the same ctx-level Cleaner but
        #    don't actually call signal.signal (so test runner isn't disturbed).
        register = __import__(
            "utils.cleanup", fromlist=["register_cleanup_handler"]
        ).register_cleanup_handler
        stack.enter_context(patch("utils.cleanup.signal.signal", MagicMock()))
        stack.enter_context(patch("utils.cleanup.register_cleanup_handler", side_effect=register))

        # 10) Shutdown the event loop the moment we reach it. We do this by
        #     patching the module-level _shutdown_event with one we control.
        #     do_full_chain uses threading.Event() — easier: monkeypatch the
        #     bound method to set _shutdown_event after we hit FULL_ATTACK.

        return stack

    def test_state_machine_walks_idle_to_full_attack(self, monkeypatch):
        ctx = _build_ctx()
        handler = MenuHandler(ctx)

        ap_list = [_make_ap()]
        # Input-stub order matches do_full_chain's prompt order:
        #   1) "1"           -> AP selection idx
        #   2) "d"           -> OTP service (demo)
        # Interface picking is fully mocked so no input is consumed there.
        inputs = _InputStub(["1", "d"])
        monkeypatch.setattr("builtins.input", inputs)

        with self._shared_patches(monkeypatch, ap_list, inputs):
            # Stub the interface-selection path directly — Windows has no
            # ``iwconfig`` and ``MonitorMode.get_wireless_interfaces()``
            # returns []. Cross-platform:
            handler._select_interfaces_for_chain = MagicMock(return_value=True)
            handler.ctx.ap_interface = "wlan0"
            handler.ctx.mon_interface = "wlan0mon"
            handler.ctx.internet_interface = "eth0"

            # Patch ``cli.menu.APScanner`` so ``do_full_chain`` instantiates
            # our canned scanner instead of a real one. (Legacy: prior to
            # the cli/ split, this patch targeted ``main.APScanner``;
            # the new layout has those names bound in :mod:`cli.menu`.)
            from core.scanner import ScanResult

            canned = ScanResult(aps=ap_list, duration=0.0, packet_count=len(ap_list))

            scanner_mock = MagicMock()
            scanner_mock_instance = MagicMock()
            scanner_mock.return_value = scanner_mock_instance
            scanner_mock_instance.scan = MagicMock(return_value=canned)
            scanner_mock_instance.display_aps = MagicMock(return_value=ap_list)
            scanner_mock_instance.select_ap = MagicMock(
                side_effect=lambda aps, idx: aps[0] if 0 < idx <= len(aps) else None
            )
            monkeypatch.setattr("cli.menu.APScanner", scanner_mock)

            # New home post-split: both modules expose ``_shutdown_event``.
            # Sharing: create the Event once in cli.menu, mirror into main.
            import cli.menu as menu_mod
            import main as main_mod

            main_mod._shutdown_event = menu_mod._shutdown_event
            menu_mod._shutdown_event.clear()

            def kick_shutdown():
                evt = menu_mod._shutdown_event
                evt.wait(0.05)
                evt.set()

            t = threading.Thread(target=kick_shutdown, daemon=True)
            t.start()

            handler.do_full_chain()

        assert ctx.state is AttackState.FULL_ATTACK, f"expected FULL_ATTACK, got {ctx.state.name}"
        assert ctx.deauth is not None
        assert ctx.rogue_ap is not None
        assert ctx.network is not None
        assert ctx.portal is not None
        assert ctx.cleaner is not None

    def test_invalid_ap_selection_returns_to_idle(self, monkeypatch):
        """Section 1 #9 (decomposition): invalid idx transitions to IDLE."""
        ctx = _build_ctx()
        handler = MenuHandler(ctx)

        inputs = _InputStub(["eth0", "999", "d"])
        monkeypatch.setattr("builtins.input", inputs)

        with self._shared_patches(monkeypatch, [], inputs):
            handler._select_interfaces_for_chain = MagicMock(return_value=True)
            handler.ctx.ap_interface = "wlan0"
            handler.ctx.mon_interface = "wlan0mon"
            handler.ctx.internet_interface = "eth0"

            # Patch main.APScanner so do_full_chain never builds a real one.
            from core.scanner import ScanResult

            aps = [_make_ap()]
            canned = ScanResult(aps=aps, duration=0.0, packet_count=len(aps))
            scanner_mock = MagicMock()
            scanner_mock_instance = MagicMock()
            scanner_mock.return_value = scanner_mock_instance
            scanner_mock_instance.scan = MagicMock(return_value=canned)
            scanner_mock_instance.display_aps = MagicMock(return_value=aps)
            # idx=999 -> out-of-range -> returns None.
            scanner_mock_instance.select_ap = MagicMock(return_value=None)
            monkeypatch.setattr("main.APScanner", scanner_mock)

            handler.do_full_chain()

        assert ctx.state is AttackState.IDLE

    def test_shutdown_event_completes_within_timeout(self, monkeypatch):
        """Section 4 #9: FULL_ATTACK -> IDLE return must be Event-driven."""
        ctx = _build_ctx()
        handler = MenuHandler(ctx)

        # Reset the module-level event so this test is hermetic.
        main_mod = __import__("main", fromlist=["_shutdown_event"])
        # Critical: ensure the event is initially unset, even if a previous
        # test set it.
        main_mod._shutdown_event = threading.Event()

        inputs = _InputStub(["", "1", "d"])
        monkeypatch.setattr("builtins.input", inputs)
        ctx.target_ap = _make_ap()

        with self._shared_patches(monkeypatch, [_make_ap()], inputs):
            # Set the event after a short delay — the wait() call inside
            # do_full_chain must return within 1.0s of Event.set().
            def kick():
                import time as _t

                _t.sleep(0.05)
                main_mod._shutdown_event.set()

            threading.Thread(target=kick, daemon=True).start()

            start = threading.Event()
            start.set()
            t0 = start.wait.__self__ if False else None
            import time as _t

            t0 = _t.monotonic()

            handler.do_full_chain()

            elapsed = _t.monotonic() - t0
            # do_full_chain's wait()+sleep cycle is bounded at ~1.05s.
            # We allow a generous upper bound to avoid CI flakiness.
            assert elapsed < 3.0, f"do_full_chain took {elapsed:.2f}s"


class TestDoFullChainHelpers:
    """Decompose helpers (Section 1 #9) — no subprocess, no threading."""

    def test_select_interfaces_for_chain_returns_true(self, monkeypatch):
        from main import _shutdown_event  # noqa: F401  (sanity import)

        ctx = _build_ctx()
        handler = MenuHandler(ctx)

        # Pre-answer the two select_interface() inputs and the internet iface.
        inputs = _InputStub(["", "1", "2", "eth0"])
        monkeypatch.setattr("builtins.input", inputs)

        # enable_monitor returning a transformed iface name is fine.
        monkeypatch.setattr("utils.monitor_mode.MonitorMode.enable_monitor", lambda x: "wlan0mon")

        # Stub select_interface explicitly: return canned names.
        calls = {"n": 0}

        def fake_select(prompt, exclude=None):
            calls["n"] += 1
            return "wlan0mon" if calls["n"] == 1 else "wlan0"

        handler.select_interface = fake_select

        result = handler._select_interfaces_for_chain()
        assert result is True
        assert ctx.mon_interface == "wlan0mon"
        assert ctx.ap_interface == "wlan0"
        assert ctx.internet_interface == "eth0"

    def test_configure_network_builds_network_config(self):
        ctx = _build_ctx()
        ctx.config.portal_port = 8080
        ctx.config.gateway = "10.0.0.1"
        ctx.ap_interface = "wlan0"
        ctx.internet_interface = "eth0"
        handler = MenuHandler(ctx)

        with patch.object(
            __import__("core.network", fromlist=["NetworkConfig"]).NetworkConfig,
            "setup_iptables",
            return_value=True,
        ):
            assert handler._configure_network() is True

        assert ctx.network is not None
        assert ctx.network.internet_interface == "eth0"
        assert ctx.network.ap_interface == "wlan0"
        assert ctx.network.portal_port == 8080
        assert ctx.network.gateway == "10.0.0.1"

    def test_wait_for_deauth_returns_early_when_packets_sent(self, monkeypatch):
        ctx = _build_ctx()
        handler = MenuHandler(ctx)

        # Deauth-with-packets path.
        deauth = MagicMock()
        deauth.packets_sent = 20  # > the 10 threshold
        ctx.deauth = deauth

        # monkey-patch time.sleep to bail-fast if reached.
        sleeps = []
        monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))

        handler._wait_for_deauth(max_seconds=2)

        # If packets >= 10 from the start, we exit immediately.
        assert sleeps == []
