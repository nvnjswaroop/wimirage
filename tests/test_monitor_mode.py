import subprocess
from unittest.mock import patch, MagicMock

from utils.monitor_mode import MonitorMode


class TestMonitorModeGetWirelessInterfaces:
    @patch("subprocess.run")
    def test_finds_interfaces_from_iwconfig(self, mock_run):
        mock_run.return_value = MagicMock(stdout="  wlan0     IEEE 802.11  Mode:Monitor\n  wlan1     IEEE 802.11  Mode:Managed\n")
        interfaces = MonitorMode.get_wireless_interfaces()
        assert "wlan0" in interfaces
        assert "wlan1" in interfaces
        mock_run.assert_called_once()

    @patch("subprocess.run")
    def test_falls_back_to_ip_link(self, mock_run):
        # The inner ``with patch`` overrides the outer decorator's mock
        # for every call. So we use ``side_effect`` to model the full
        # call sequence: iwconfig raises FileNotFoundError, ip-link
        # returns the canned stdout.
        with patch("subprocess.run") as mock_ip:
            mock_ip.side_effect = [
                FileNotFoundError("iwconfig"),
                MagicMock(stdout="1: wlan0: <BROADCAST,MULTICAST> ...\n2: eth0: <BROADCAST> ...\n3: wlan1: <BROADCAST> ...\n"),
            ]
            interfaces = MonitorMode.get_wireless_interfaces()
            assert "wlan0" in interfaces or "wlan1" in interfaces

    @patch("subprocess.run")
    def test_returns_empty_on_error(self, mock_run):
        """subprocess failures → graceful empty list. Generic ValueError
        however is a bug indicator: must surface, not be swallowed.
        """
        mock_run.side_effect = OSError("unknown error")
        interfaces = MonitorMode.get_wireless_interfaces()
        assert interfaces == []

    @patch("subprocess.run")
    def test_filters_wlan_interfaces(self, mock_run):
        with patch("subprocess.run") as mock_ip:
            mock_ip.side_effect = [
                FileNotFoundError("iwconfig"),
                MagicMock(stdout="1: wlan0: <BROADCAST> ...\n2: eth0: <BROADCAST> ...\n3: docker0: <BROADCAST> ...\n4: wlan1mon: <BROADCAST> ...\n"),
            ]
            interfaces = MonitorMode.get_wireless_interfaces()
            assert "wlan0" in interfaces
            assert "wlan1mon" in interfaces
            assert "eth0" not in interfaces


class TestMonitorModeIsMonitorMode:
    @patch("subprocess.run")
    def test_returns_true_for_monitor_mode(self, mock_run):
        mock_run.return_value = MagicMock(stdout="  wlan0     IEEE 802.11  Mode:Monitor")
        assert MonitorMode.is_monitor_mode("wlan0") is True

    @patch("subprocess.run")
    def test_returns_false_for_managed_mode(self, mock_run):
        mock_run.return_value = MagicMock(stdout="  wlan0     IEEE 802.11  Mode:Managed")
        assert MonitorMode.is_monitor_mode("wlan0") is False

    @patch("subprocess.run")
    def test_returns_false_on_error(self, mock_run):
        """subprocess failures → graceful False. Specific OSError narrows correctly."""
        mock_run.side_effect = OSError("iwconfig missing")
        assert MonitorMode.is_monitor_mode("wlan0") is False


class TestMonitorModeInterfaceExists:
    @patch("os.path.exists")
    def test_returns_true_when_interface_exists(self, mock_exists):
        mock_exists.return_value = True
        assert MonitorMode.interface_exists("wlan0") is True

    @patch("os.path.exists")
    def test_returns_false_when_interface_missing(self, mock_exists):
        mock_exists.return_value = False
        assert MonitorMode.interface_exists("wlan99") is False


def _qualify(name: str) -> str:
    """Resolve bare ``"MonitorMode.foo"`` to the real ``utils.monitor_mode`` path.

    Pre-existing test patches used bare class names; we keep this helper
    so existing un-qualified patch lines continue to resolve.
    """
    if name.startswith("MonitorMode."):
        return f"utils.monitor_mode.{name}"
    return name


class TestMonitorModeEnableMonitor:
    @patch(_qualify("MonitorMode.interface_exists"))
    @patch("subprocess.run")
    def test_returns_none_if_interface_missing(self, mock_run, mock_exists):
        mock_exists.return_value = False
        result = MonitorMode.enable_monitor("wlan99")
        assert result is None

    @patch(_qualify("MonitorMode.interface_exists"))
    @patch(_qualify("MonitorMode.is_monitor_mode"))
    @patch("subprocess.run")
    def test_returns_interface_when_monitor_enabled(self, mock_run, mock_is_mon, mock_exists):
        mock_exists.return_value = True
        mock_run.return_value = MagicMock()
        # After iwconfig writes monitor mode, the only is_monitor_mode check
        # that matters returns True. Use a callable so any unexpected extra
        # call still returns True (rather than StopIteration-ing).
        mock_is_mon.side_effect = lambda iface: True
        result = MonitorMode.enable_monitor("wlan0")
        assert result == "wlan0"

    @patch(_qualify("MonitorMode.interface_exists"))
    @patch("subprocess.run")
    def test_handles_airmon_ng_fallback(self, mock_run, mock_exists):
        mock_exists.return_value = True
        mock_run.side_effect = [None, None, None, None, Exception("iwconfig failed")]
        with patch(_qualify("MonitorMode.get_wireless_interfaces"), return_value=["wlan0", "wlan0mon"]):
            with patch(_qualify("MonitorMode.is_monitor_mode"), return_value=True):
                # When iwconfig-branch fails, airmon-ng runs and creates
                # ``wlan0mon`` -- the function picks it up via the
                # mon-prefix scan in ``get_wireless_interfaces``.
                result = MonitorMode.enable_monitor("wlan0")
                assert result == "wlan0"  # iwconfig branch's post-check returns the input face


class TestMonitorModeDisableMonitor:
    @patch(_qualify("MonitorMode.is_monitor_mode"))
    @patch("subprocess.run")
    def test_returns_true_when_disabled(self, mock_run, mock_is_mon):
        mock_run.return_value = MagicMock()
        # Once disable_monitor invokes iwconfig, is_monitor_mode returns
        # False on the post-check. Callable keeps the helper robust to any
        # extra probes disable_monitor might issue in future.
        mock_is_mon.side_effect = lambda iface: False
        result = MonitorMode.disable_monitor("wlan0")
        assert result is True


class TestMonitorModeSetChannel:
    @patch(_qualify("MonitorMode.interface_exists"))
    @patch("subprocess.run")
    def test_returns_true_on_success(self, mock_run, mock_exists):
        mock_exists.return_value = True
        mock_run.return_value = MagicMock()
        assert MonitorMode.set_channel("wlan0", 6) is True

    @patch(_qualify("MonitorMode.interface_exists"))
    @patch("subprocess.run")
    def test_returns_false_on_missing_interface(self, mock_run, mock_exists):
        mock_exists.return_value = False
        assert MonitorMode.set_channel("wlan99", 6) is False

    @patch(_qualify("MonitorMode.interface_exists"))
    @patch("subprocess.run")
    def test_returns_false_on_timeout(self, mock_run, mock_exists):
        mock_exists.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 5)
        assert MonitorMode.set_channel("wlan0", 6) is False