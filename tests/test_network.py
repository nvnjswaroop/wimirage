"""Tests for core.network (Section 7 updates).

The bulk of these tests exercise ``NetworkConfig`` and ``flush_iptables``
with ``subprocess.run`` fully mocked so they pass in any environment
(Windows, macOS, headless Linux, …) without needing iptables binaries.
"""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from core.network import (
    FILTER_TABLE_TEMPLATE,
    NAT_TABLE_TEMPLATE,
    NetworkConfig,
    flush_iptables,
)

# ---------------------------------------------------------------------------
# Section 7 #9 — grant_internet assertions
# ---------------------------------------------------------------------------


class TestGrantInternet:
    """Section 7 #9: assert the right iptables -I command is built."""

    def _nc(self):
        return NetworkConfig("eth0", "wlan0", portal_port=80, gateway="10.0.0.1")

    @patch("subprocess.run")
    def test_emits_prerouting_insert_rule(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        nc = self._nc()

        result = nc.grant_internet("10.0.0.25")

        assert result is True
        mock_run.assert_called_once_with(
            [
                "iptables",
                "-t",
                "nat",
                "-I",
                "PREROUTING",
                "1",
                "-s",
                "10.0.0.25",
                "-p",
                "tcp",
                "--dport",
                "80",
                "-j",
                "ACCEPT",
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

    @patch("subprocess.run")
    def test_dedupes_per_ip(self, mock_run):
        """Calling twice for the same IP only inserts once."""
        mock_run.return_value = MagicMock(returncode=0)
        nc = self._nc()
        nc.grant_internet("10.0.0.25")
        nc.grant_internet("10.0.0.25")
        nc.grant_internet("10.0.0.26")

        assert mock_run.call_count == 2
        assert nc._granted_ips == {"10.0.0.25", "10.0.0.26"}

    @patch("subprocess.run")
    def test_returns_false_on_iptables_failure(self, mock_run):
        """Section 4 #10: iptables rule-insert failure must surface."""
        mock_run.return_value = MagicMock(returncode=1, stderr="boom")
        nc = self._nc()

        assert nc.grant_internet("10.0.0.25") is False
        # Failed iptables call must NOT mark the IP as granted (retry-able).
        assert nc._granted_ips == set()

    @patch("subprocess.run", side_effect=OSError("iptables missing"))
    def test_returns_false_on_subprocess_oserror(self, mock_run):
        """OSError spawning iptables → graceful swallow → return False."""
        nc = self._nc()
        assert nc.grant_internet("10.0.0.25") is False
        assert mock_run.called

    @patch("subprocess.run", side_effect=OSError("iptables missing"))
    def test_returns_false_on_subprocess_timeout(self, mock_run):
        """TimeoutExpired while invoking the rule → graceful swallow."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="iptables", timeout=10)
        nc = self._nc()
        assert nc.grant_internet("10.0.0.25") is False
        assert "10.0.0.25" not in nc._granted_ips


# ---------------------------------------------------------------------------
# flush_iptables
# ---------------------------------------------------------------------------


class TestFlushIptables:
    @patch("subprocess.run")
    def test_flush_runs_four_iptables_commands(self, mock_run):
        mock_run.return_value = MagicMock()
        flush_iptables()
        assert mock_run.call_count >= 4
        calls = [c.args[0] for c in mock_run.call_args_list]
        # First chain clearance.
        assert ["iptables", "-F"] in calls
        # NAT chain clearance.
        assert ["iptables", "-t", "nat", "-F"] in calls
        # Both chain removals.
        assert ["iptables", "-X"] in calls
        assert ["iptables", "-t", "nat", "-X"] in calls

    @patch("subprocess.run")
    def test_flush_handles_subprocess_errors_gracefully(self, mock_run):
        """subprocess.TimeoutExpired + OSError are caught; never bubble up."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="iptables", timeout=10)
        # No exception escapes.
        flush_iptables()

    @patch("subprocess.run")
    def test_flush_propagates_unexpected_errors(self, mock_run):
        """Generic ValueError is NOT swallowed — debuggability > silence.
        Narrowing ``except Exception`` to specific types means genuine bugs
        surface during testing instead of being silently logged.
        """
        mock_run.side_effect = ValueError("logic bug")
        with pytest.raises(ValueError, match="logic bug"):
            flush_iptables()

    @patch("subprocess.run")
    def test_flush_uses_devnull_for_output(self, mock_run):
        mock_run.return_value = MagicMock()
        flush_iptables()
        for c in mock_run.call_args_list:
            assert c.kwargs.get("stdout") is subprocess.DEVNULL
            assert c.kwargs.get("stderr") is subprocess.DEVNULL
            assert c.kwargs.get("timeout") == 10


# ---------------------------------------------------------------------------
# NetworkConfig — ip_forward toggle + constructor invariants
# ---------------------------------------------------------------------------


class TestNetworkConfigInit:
    def test_default_port_and_gateway(self):
        nc = NetworkConfig("eth0", "wlan0")
        assert nc.internet_interface == "eth0"
        assert nc.ap_interface == "wlan0"
        assert nc.portal_port == NetworkConfig.DEFAULT_PORTAL_PORT
        assert nc.gateway == NetworkConfig.DEFAULT_GATEWAY
        assert nc._granted_ips == set()

    def test_overrides(self):
        nc = NetworkConfig("eth0", "wlan0", portal_port=8443, gateway="192.168.1.1")
        assert nc.portal_port == 8443
        assert nc.gateway == "192.168.1.1"


class TestEnableIpForwarding:
    @patch("builtins.open", new_callable=MagicMock)
    def test_writes_1(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        nc = NetworkConfig("eth0", "wlan0")

        assert nc.enable_ip_forwarding() is True
        mock_file.write.assert_called_with("1")

    @patch("builtins.open", side_effect=PermissionError)
    def test_permission_error_returns_false(self, _):
        nc = NetworkConfig("eth0", "wlan0")
        assert nc.enable_ip_forwarding() is False

    @patch("builtins.open", side_effect=OSError("disk gone"))
    def test_io_error_returns_false(self, _):
        nc = NetworkConfig("eth0", "wlan0")
        assert nc.enable_ip_forwarding() is False


class TestDisableIpForwarding:
    @patch("builtins.open", new_callable=MagicMock)
    def test_writes_0(self, mock_open):
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        nc = NetworkConfig("eth0", "wlan0")
        nc.disable_ip_forwarding()
        mock_file.write.assert_called_with("0")


# ---------------------------------------------------------------------------
# setup_iptables — iptables-restore succeeds / falls back
# ---------------------------------------------------------------------------


class TestSetupIptables:
    @patch("core.network.restore_iptables", create=True)
    @patch("core.network.backup_iptables", create=True)
    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    def test_restore_success(self, mock_temp, mock_run, _mock_backup, _mock_restore, tmp_path):
        """When iptables-restore returns 0, setup_iptables returns True."""
        mock_file = MagicMock()
        mock_file.name = "/tmp/rules.123"
        mock_temp.return_value.__enter__.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=0, stderr="")
        nc = NetworkConfig("eth0", "wlan0")
        assert nc.setup_iptables() is True

        # Check the restore command references both rendered templates.
        restore_call = None
        for c in mock_run.call_args_list:
            if c.args and c.args[0][0] == "iptables-restore":
                restore_call = c
                break
        assert restore_call is not None
        assert restore_call.args[0][1] == "/tmp/rules.123"

    @patch("core.network.restore_iptables", create=True)
    @patch("core.network.backup_iptables", create=True)
    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    @patch("os.unlink")
    def test_restore_failure_returns_false(
        self, mock_unlink, mock_temp, mock_run, _mock_backup, _mock_restore
    ):
        mock_file = MagicMock()
        mock_file.name = "/tmp/rules.123"
        mock_temp.return_value.__enter__.return_value = mock_file

        mock_run.return_value = MagicMock(returncode=1, stderr="bad rules")
        nc = NetworkConfig("eth0", "wlan0")
        assert nc.setup_iptables() is False

    @patch("core.network.restore_iptables", create=True)
    @patch("core.network.backup_iptables", create=True)
    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    @patch("os.unlink")
    def test_restore_falls_back_to_individual_rules(
        self, mock_unlink, mock_temp, mock_run, _mock_backup, _mock_restore
    ):
        # First subprocess.run is iptables-restore inside setup_iptables.
        # Raise FileNotFoundError to trigger the fallback branch.
        mock_file = MagicMock()
        mock_file.name = "/tmp/rules.123"
        mock_temp.return_value.__enter__.return_value = mock_file

        nc = NetworkConfig("eth0", "wlan0")

        # Two contexts: outer (iptables-restore raises) and fallback (subprocess succeeds).
        with patch("subprocess.run") as restore_run:
            restore_run.side_effect = FileNotFoundError  # only the restore call
            # fallback path uses subprocess.run inside _setup_iptables_fallback
            with patch("core.network.subprocess.run") as fallback_run:
                fallback_run.return_value = MagicMock(returncode=0)
                # also avoid writing to /proc/sys/net/ipv4/ip_forward
                with patch.object(NetworkConfig, "enable_ip_forwarding", return_value=True):
                    assert nc.setup_iptables() is True


class TestCleanup:
    def test_cleanup_clears_granted_ips(self):
        nc = NetworkConfig("eth0", "wlan0")
        nc._granted_ips.add("10.0.0.25")
        nc._granted_ips.add("10.0.0.26")

        with (
            patch("core.network.flush_iptables"),
            patch.object(NetworkConfig, "disable_ip_forwarding"),
        ):
            nc.cleanup()

        assert nc._granted_ips == set()


# ---------------------------------------------------------------------------
# Section 7 #6 template sanity (Section 6 #10)
# ---------------------------------------------------------------------------


class TestTemplates:
    """The templates are constants — but the format placeholders matter."""

    def test_nat_template_placeholders(self):
        for token in (
            "{ap_interface}",
            "{internet_interface}",
            "{gateway}",
            "{portal_port}",
            "PREROUTING",
            "MASQUERADE",
            "COMMIT",
            "DNAT",
        ):
            assert token in NAT_TABLE_TEMPLATE, f"NAT_TEMPLATE missing {token}"

    def test_filter_template_placeholders(self):
        for token in ("{ap_interface}", "{internet_interface}", "RELATED,ESTABLISHED", "COMMIT"):
            assert token in FILTER_TABLE_TEMPLATE, f"FILTER_TEMPLATE missing {token}"
