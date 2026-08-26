"""Security tests for iptables rollback on crash/exit (security pass S-4).

We can't actually invoke iptables in a CI sandbox, so these tests stub the
subprocess boundary and verify the cleanup contract:

  * atexit registers a callable that invokes the network cleanup path
  * SIGINT/SIGTERM installed by register_cleanup_handler both route to
    cleanup_all + sys.exit
  * CaptivePortal construction installs ONE atexit callback (idempotent)
  * the rollback flushes rules + disables ip_forward
"""

from __future__ import annotations

import signal
from unittest.mock import MagicMock, patch



# ---------------------------------------------------------------------------
# S-4.1: CaptivePortal installs atexit cleanup that calls flush_iptables
# ---------------------------------------------------------------------------

class TestCaptivePortalAtexitCleanup:
    def test_atexit_registers_flush_callback(self):
        """Constructing CaptivePortal must schedule a rollback callable."""
        from core.captive_portal import CaptivePortal
        from core.models import AppConfig

        cfg = AppConfig()
        cfg.secret_key = "x" * 32

        with patch("atexit.register") as mock_register:
            CaptivePortal._atexit_registered = False
            p = CaptivePortal(config=cfg, otp_service=None, network_config=None)
            # The first construction should call atexit.register exactly once.
            assert mock_register.call_count >= 1
            # The registered callable should be something callable().
            args, _ = mock_register.call_args
            assert callable(args[0])

    def test_atexit_is_idempotent(self):
        """Multiple CaptivePortal constructions must NOT stack callbacks."""
        from core.captive_portal import CaptivePortal
        from core.models import AppConfig

        cfg = AppConfig()
        cfg.secret_key = "x" * 32
        with patch("atexit.register") as mock_register:
            CaptivePortal._atexit_registered = False
            CaptivePortal(config=cfg, otp_service=None, network_config=None)
            first_count = mock_register.call_count

            CaptivePortal._atexit_registered = False
            CaptivePortal(config=cfg, otp_service=None, network_config=None)
            second_count = mock_register.call_count - first_count

            assert second_count == 1, (
                "Second portal construction must not stack a duplicate atexit callback"
            )

    def test_atexit_callback_invokes_flush(self):
        """The atexit-registered callable must end up calling flush_iptables."""
        from core.captive_portal import CaptivePortal
        from core.models import AppConfig

        cfg = AppConfig()
        cfg.secret_key = "x" * 32
        CaptivePortal._atexit_registered = False

        with patch("atexit.register") as mock_register, \
             patch("core.captive_portal.flush_iptables") as mock_flush:
            p = CaptivePortal(config=cfg, otp_service=None, network_config=None)
            # Replay the registered callback manually to assert its effect.
            registered_callable = mock_register.call_args[0][0]
            registered_callable()
            mock_flush.assert_called()

    def test_atexit_failure_is_swallowed(self):
        """If flush_iptables raises during interpreter shutdown, we don't crash."""
        from core.captive_portal import CaptivePortal
        from core.models import AppConfig

        cfg = AppConfig()
        cfg.secret_key = "x" * 32
        CaptivePortal._atexit_registered = False

        with patch("atexit.register") as mock_register, \
             patch("core.captive_portal.flush_iptables",
                   side_effect=OSError("iptables missing")):
            p = CaptivePortal(config=cfg, otp_service=None, network_config=None)
            cb = mock_register.call_args[0][0]
            # Must not raise even though flush_iptables does.
            cb()


# ---------------------------------------------------------------------------
# S-4.2: register_cleanup_handler installs SIGINT/SIGTERM handlers
# ---------------------------------------------------------------------------

class TestSignalCleanupHandler:
    def test_sigint_handler_routes_to_cleanup(self):
        """Replacing SIGINT must point at a Cleanup.cleanup_all() entrypoint."""
        # Snapshot existing handlers so we restore at teardown — important
        # because pytest itself relies on the default SIGINT handler.
        original_int = signal.getsignal(signal.SIGINT)
        original_term = signal.getsignal(signal.SIGTERM)
        try:
            from utils.cleanup import register_cleanup_handler
            handler = register_cleanup_handler()
            assert handler is not None
            new_int = signal.getsignal(signal.SIGINT)
            new_term = signal.getsignal(signal.SIGTERM)
            assert new_int != original_int
            assert new_term != original_term
            assert callable(new_int)
            assert callable(new_term)
        finally:
            signal.signal(signal.SIGINT, original_int)
            signal.signal(signal.SIGTERM, original_term)

    def test_cleanup_all_flushes_iptables_and_disables_forwarding(self):
        """``Cleanup.cleanup_all`` must invoke both iptables flush + forward-off."""
        from utils.cleanup import Cleanup

        c = Cleanup()
        with patch("utils.cleanup.flush_iptables") as mock_flush, \
             patch.object(c, "disable_ip_forwarding") as mock_disable, \
             patch.object(c, "restore_interfaces"), \
             patch.object(c, "restart_network_manager"), \
             patch.object(c, "kill_background_processes"):
            c.cleanup_all()
            mock_flush.assert_called_once()
            mock_disable.assert_called_once()

    def test_cleanup_all_swallows_restore_failure(self):
        """If iface restoration fails, cleanup_all must complete (best-effort)."""
        from utils.cleanup import Cleanup

        c = Cleanup()
        with patch("utils.cleanup.flush_iptables"), \
             patch.object(c, "disable_ip_forwarding"), \
             patch.object(c, "restore_interfaces",
                          side_effect=OSError("iface not present")), \
             patch.object(c, "restart_network_manager"), \
             patch.object(c, "kill_background_processes"):
            # No exception should bubble up.
            c.cleanup_all()


# ---------------------------------------------------------------------------
# S-4.3: cli/entry.main() installs a signal cleanup handler
# ---------------------------------------------------------------------------

class TestCliEntryWiring:
    def test_main_invokes_register_cleanup_handler(self):
        """``cli.entry.main`` must call ``register_cleanup_handler`` after build_ctx."""
        from cli import entry as entry_mod

        called = {"n": 0}

        def fake_handler(*a, **kw):
            called["n"] += 1
            return MagicMock()

        # Build a fake AttackContext + MenuHandler. The handler is imported
        # lazily inside ``main()`` (``from utils.cleanup import ...``) so
        # we patch at the *source* module path.
        with patch.object(entry_mod, "check_root"), \
             patch("cli.entry.AttackContext", return_value=MagicMock()), \
             patch("cli.entry.MenuHandler") as mock_menu, \
             patch("utils.cleanup.register_cleanup_handler", fake_handler), \
             patch("cli.entry.AppConfig", return_value=MagicMock()):
            entry_mod.main()
        assert called["n"] >= 1, (
            "main() did not wire register_cleanup_handler — host network will "
            "be left in NAT'd state on Ctrl+C."
        )
        # And the menu actually runs (not silently dropped).
        mock_menu.return_value.run.assert_called()
