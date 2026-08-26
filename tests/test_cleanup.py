import signal
from unittest.mock import ANY, MagicMock, patch

import pytest

from utils.cleanup import Cleanup, register_cleanup_handler


class TestCleanup:
    def test_init_default_values(self):
        cleaner = Cleanup()
        assert cleaner.interfaces == []
        assert cleaner.internet_interface is None
        assert cleaner._processes == []

    def test_init_with_interfaces(self):
        cleaner = Cleanup(interfaces=["wlan0", "wlan1"], internet_interface="eth0")
        assert cleaner.interfaces == ["wlan0", "wlan1"]
        assert cleaner.internet_interface == "eth0"

    def test_register_process(self):
        cleaner = Cleanup()
        mock_proc = MagicMock()
        cleaner.register_process(mock_proc)
        assert mock_proc in cleaner._processes

    @patch("subprocess.run")
    def test_kill_background_processes_kills_hostapd(self, mock_run):
        # Section 7 #3: cleanup.py keeps capture_output=True here because the
        # only signal we want is result.returncode. Stub returncode=0 so the
        # retry loop succeeds on the first try.
        # password leak from observed leaks in older revisions of cleanup.py
        # — current implementation no longer captures stdout/stderr.
        mock_run.return_value = MagicMock(returncode=0)
        cleaner = Cleanup()
        cleaner.kill_background_processes()
        # Both hostapd and dnsmasq should have been targeted with killing commands.
        cmd_targets = {c.args[0][1] for c in mock_run.call_args_list if c.args}
        assert "hostapd" in cmd_targets
        assert "dnsmasq" in cmd_targets
        # Each call has capture_output=True (count is what cerrar ()  uses).
        for c in mock_run.call_args_list:
            assert c.kwargs.get("capture_output") is True, f"unexpected keyword: {c.kwargs}"

    @patch("subprocess.run")
    def test_disable_ip_forwarding(self, mock_run):
        cleaner = Cleanup()
        with patch("builtins.open", MagicMock()):
            cleaner.disable_ip_forwarding()

    @patch("subprocess.run")
    def test_restart_network_manager_ignores_errors(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        cleaner = Cleanup()
        cleaner.restart_network_manager()

    @patch("subprocess.run")
    def test_cleanup_all_sequence(self, mock_run):
        mock_run.return_value = MagicMock()
        cleaner = Cleanup(interfaces=["wlan0"])
        with patch.object(cleaner, "kill_background_processes") as mock_kill:
            with patch.object(cleaner, "disable_ip_forwarding") as mock_ipf:
                with patch("utils.cleanup.flush_iptables"):
                    with patch.object(cleaner, "restore_interfaces"):
                        with patch.object(cleaner, "restart_network_manager"):
                            cleaner.cleanup_all()


class TestRegisterCleanupHandler:
    @patch("signal.signal")
    def test_returns_cleanup_instance(self, mock_signal):
        cleaner = register_cleanup_handler(interfaces=["wlan0"])
        assert isinstance(cleaner, Cleanup)
        assert cleaner.interfaces == ["wlan0"]

    @patch("signal.signal")
    def test_registers_sigint_handler(self, mock_signal):
        register_cleanup_handler()
        mock_signal.assert_any_call(signal.SIGINT, ANY)

    @patch("signal.signal")
    def test_registers_sigterm_handler(self, mock_signal):
        register_cleanup_handler()
        mock_signal.assert_any_call(signal.SIGTERM, ANY)


class TestSigintHandlerInvokesCleanup:
    """Section 7 #12: SIGINT triggers Cleanup.cleanup_all() then sys.exit(0).

    We can't actually send a Unix SIGINT from inside pytest-threaded code on
    Windows/Linux easily — so we exercise the registered handler directly.
    """

    @patch("sys.exit", new_callable=MagicMock)
    @patch("signal.signal")
    @patch("utils.cleanup.flush_iptables")
    @patch("utils.cleanup.Cleanup.cleanup_all")
    def test_sigint_invokes_cleanup_all(self, mock_cleanup_all, mock_flush, mock_signal, mock_exit):
        from utils.cleanup import register_cleanup_handler

        cleaner = register_cleanup_handler(interfaces=["wlan0"])

        # Pull the SIGINT handler out of the captured signal.signal calls.
        sigint_handler = None
        for c in mock_signal.call_args_list:
            if c.args[0] == signal.SIGINT:
                sigint_handler = c.args[1]
                break
        assert sigint_handler is not None, "SIGINT handler was not registered"

        # Fire it with the canonical (signum, frame) signature.
        sigint_handler(signal.SIGINT, None)

        mock_cleanup_all.assert_called_once()
        mock_exit.assert_called_once_with(0)

    @patch("sys.exit", new_callable=MagicMock)
    @patch("signal.signal")
    @patch("utils.cleanup.flush_iptables")
    @patch("utils.cleanup.Cleanup.cleanup_all")
    def test_sigterm_invokes_cleanup_all(
        self, mock_cleanup_all, mock_flush, mock_signal, mock_exit
    ):
        from utils.cleanup import register_cleanup_handler

        register_cleanup_handler(interfaces=["wlan0mon"], internet_interface="eth0")

        sigterm_handler = None
        for c in mock_signal.call_args_list:
            if c.args[0] == signal.SIGTERM:
                sigterm_handler = c.args[1]
                break
        assert sigterm_handler is not None, "SIGTERM handler was not registered"

        sigterm_handler(signal.SIGTERM, None)
        mock_cleanup_all.assert_called_once()


class TestRetryDecorator:
    """Section 4 #3: the @retry decorator behavior is the public contract."""

    def test_succeeds_after_transient_failures(self):
        from utils.cleanup import retry

        calls = {"n": 0}

        @retry(max_attempts=3, delay=0.0, exceptions=(RuntimeError,))
        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("blip")
            return "ok"

        assert flaky() == "ok"
        assert calls["n"] == 3

    def test_raises_after_exhausting_attempts(self):
        from utils.cleanup import retry

        @retry(max_attempts=2, delay=0.0, exceptions=(RuntimeError,))
        def always_broken():
            raise RuntimeError("nope")

        with pytest.raises(RuntimeError):
            always_broken()

    def test_unrelated_exceptions_propagate_immediately(self):
        """Decorate with a narrow exception class — ValueError must skip retry."""
        from utils.cleanup import retry

        calls = {"n": 0}

        @retry(max_attempts=3, delay=0.0, exceptions=(RuntimeError,))
        def boom():
            calls["n"] += 1
            raise ValueError("not retried")

        with pytest.raises(ValueError):
            boom()
        assert calls["n"] == 1
