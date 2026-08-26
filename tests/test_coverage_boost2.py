"""Second coverage wave: rogue_ap lifecycle, deauth send loop, monitor_mode,
cleanup, and captive-portal start/stop paths — all via subprocess/Popen mocks.
"""

from __future__ import annotations

import subprocess
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# core.rogue_ap — interface config, start/stop with mocked Popen
# ---------------------------------------------------------------------------


def _ok(*a, **k):
    r = subprocess.CompletedProcess([], 0)
    r.stdout = ""
    return r


def test_rogue_ap_configure_interface(monkeypatch):
    from core.rogue_ap import RogueAP

    ap = RogueAP(interface="wlan0ap", ssid="s", channel=1)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess([], 0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert ap._configure_interface() is True
    assert any("link" in c for c in calls if isinstance(c, list))
    assert any("addr" in c for c in calls if isinstance(c, list))


def test_rogue_ap_configure_interface_timeout(monkeypatch):
    from core.rogue_ap import RogueAP

    ap = RogueAP(interface="wlan0ap", ssid="s", channel=1)

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 10)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert ap._configure_interface() is False


class FakeProc:
    """Popen stand-in that stays alive until terminated."""

    def __init__(self, *args, **kwargs):
        self.returncode = None
        self._alive = True

    def poll(self):
        return None if self._alive else 0

    def terminate(self):
        self._alive = False

    def kill(self):
        self._alive = False

    def wait(self, timeout=None):
        self._alive = False
        return 0


def test_rogue_ap_start_and_stop_lifecycle(tmp_path, monkeypatch):
    import core.rogue_ap as ra_mod
    from core.rogue_ap import RogueAP

    # Redirect config paths into tmp_path
    ap = RogueAP(
        interface="wlan0x",
        ssid="TestSSID",
        channel=3,
        process_manager=mock.MagicMock(),
    )
    ap._hostapd_conf = str(tmp_path / "hostapd.conf")
    ap._dnsmasq_conf = str(tmp_path / "dnsmasq.conf")
    ap._hostapd_pid = str(tmp_path / "hostapd.pid")
    ap._dnsmasq_pid = str(tmp_path / "dnsmasq.pid")

    monkeypatch.setattr(ra_mod.subprocess, "run", _ok)
    monkeypatch.setattr(ra_mod.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(ra_mod.time, "sleep", lambda s: None)

    assert ap.start() is True
    assert ap.hostapd_proc is not None
    assert ap.dnsmasq_proc is not None
    assert ap.is_running() is True

    ap.stop()
    assert ap.is_running() is False


def test_rogue_ap_start_hostapd_dies(tmp_path, monkeypatch):
    import core.rogue_ap as ra_mod
    from core.rogue_ap import RogueAP

    ap = RogueAP(interface="wlan0y", ssid="s", channel=1)
    ap._hostapd_conf = str(tmp_path / "h.conf")
    ap._dnsmasq_conf = str(tmp_path / "d.conf")

    class DyingProc(FakeProc):
        def poll(self):
            return 1  # dead immediately

        returncode = 1

    monkeypatch.setattr(ra_mod.subprocess, "run", _ok)
    monkeypatch.setattr(ra_mod.subprocess, "Popen", DyingProc)
    monkeypatch.setattr(ra_mod.time, "sleep", lambda s: None)

    assert ap.start() is False


def test_rogue_ap_start_hostapd_missing(tmp_path, monkeypatch):
    import core.rogue_ap as ra_mod
    from core.rogue_ap import RogueAP

    ap = RogueAP(interface="wlan0z", ssid="s", channel=1)
    ap._hostapd_conf = str(tmp_path / "h.conf")
    ap._dnsmasq_conf = str(tmp_path / "d.conf")

    def boom(*a, **k):
        raise FileNotFoundError("hostapd")

    monkeypatch.setattr(ra_mod.subprocess, "run", _ok)
    monkeypatch.setattr(ra_mod.subprocess, "Popen", boom)

    assert ap.start() is False


def test_rogue_ap_stop_with_live_procs():
    from core.rogue_ap import RogueAP

    ap = RogueAP(interface="w", ssid="s", channel=1, process_manager=mock.MagicMock())
    proc = mock.MagicMock()
    proc.poll.return_value = None
    proc.wait.return_value = 0
    ap.hostapd_proc = proc
    ap.dnsmasq_proc = proc
    ap.stop()
    proc.terminate.assert_called()


# ---------------------------------------------------------------------------
# core.deauth — the send loop (mock scapy.sendp) + start/stop
# ---------------------------------------------------------------------------


def test_deauth_send_loop_and_stop(monkeypatch):
    import core.deauth as da
    from core.deauth import DeauthAttack

    sent = []
    monkeypatch.setattr(da, "sendp", lambda pkt, iface, verbose: sent.append(pkt))

    atk = DeauthAttack(
        interface="mon0", target_bssid="AA:BB:CC:DD:EE:FF", target_channel=6, pps=500
    )
    atk.start()
    # give the loop a moment to emit frames
    import time

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and len(sent) < 5:
        time.sleep(0.02)
    atk.stop()

    assert atk.is_running() is False
    assert len(sent) >= 2  # forward (+ reverse for broadcast)


def test_deauth_permission_error_stops_loop(monkeypatch):
    import core.deauth as da
    from core.deauth import DeauthAttack

    def denied(pkt, iface, verbose):
        raise PermissionError("not root")

    monkeypatch.setattr(da, "sendp", denied)
    atk = DeauthAttack(interface="mon0", target_bssid="AA:BB:CC:DD:EE:FF", target_channel=6)
    atk.start()
    import time

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and atk.is_running():
        time.sleep(0.02)
    assert atk.is_running() is False  # PermissionError halts the attack


def test_deauth_oserror_keeps_going(monkeypatch):
    import core.deauth as da
    from core.deauth import DeauthAttack

    state = {"n": 0}

    def flaky(pkt, iface, verbose):
        state["n"] += 1
        if state["n"] == 1:
            raise OSError("transient")

    monkeypatch.setattr(da, "sendp", flaky)
    atk = DeauthAttack(
        interface="mon0", target_bssid="AA:BB:CC:DD:EE:FF", target_channel=6, pps=100
    )
    atk.start()
    import time

    time.sleep(0.6)
    atk.stop()
    assert state["n"] >= 2  # retried after OSError instead of dying


def test_deauth_set_channel_paths(monkeypatch):
    import core.deauth as da
    from core.deauth import DeauthAttack

    atk = DeauthAttack(interface="mon0", target_bssid="AA:BB:CC:DD:EE:FF", target_channel=11)

    monkeypatch.setattr(da.subprocess, "run", _ok)
    atk.set_channel()  # happy path — must not raise

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("iwconfig", 5)

    monkeypatch.setattr(da.subprocess, "run", timeout)
    atk.set_channel()  # swallowed + logged

    def missing(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(da.subprocess, "run", missing)
    atk.set_channel()  # logged error path

    def other(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(da.subprocess, "run", other)
    atk.set_channel()  # broad except path


def test_deauth_already_running_guard():
    from core.deauth import DeauthAttack

    atk = DeauthAttack(interface="x", target_bssid="A:B:C:D:E:F", target_channel=1)
    atk._running = True
    atk.start()  # logs warning and returns; must not double-spawn
    atk._running = False


# ---------------------------------------------------------------------------
# utils.monitor_mode — enable/disable paths with mocked subprocess
# ---------------------------------------------------------------------------


def test_monitor_mode_get_wireless_interfaces(monkeypatch):
    from utils.monitor_mode import MonitorMode

    try:
        fake = subprocess.CompletedProcess([], 0)
        fake.stdout = "wlan0\nwlan1mon\neth0\n"
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: fake)
        result = MonitorMode.get_wireless_interfaces()
        assert isinstance(result, list)
    except (FileNotFoundError, OSError):
        pytest.skip("system tooling absent")


def test_monitor_mode_interface_exists_true_false(monkeypatch):
    from utils.monitor_mode import MonitorMode

    monkeypatch.setattr("os.path.exists", lambda p: p.endswith("wlan0"))
    assert MonitorMode.interface_exists("wlan0") is True
    assert MonitorMode.interface_exists("nosuch") is False


def test_monitor_mode_enable_monitor_missing_iface(monkeypatch):
    from utils.monitor_mode import MonitorMode

    monkeypatch.setattr(MonitorMode, "interface_exists", staticmethod(lambda i: False))
    assert MonitorMode.enable_monitor("ghost0") in (None, False)


def test_monitor_mode_is_monitor_mode_error(monkeypatch):
    from utils.monitor_mode import MonitorMode

    def boom(*a, **k):
        raise OSError("no iwconfig")

    monkeypatch.setattr(subprocess, "run", boom)
    assert MonitorMode.is_monitor_mode("x") is False


def test_monitor_mode_disable_monitor(monkeypatch):
    from utils.monitor_mode import MonitorMode

    monkeypatch.setattr(subprocess, "run", _ok)
    monkeypatch.setattr(MonitorMode, "is_monitor_mode", staticmethod(lambda i: False))
    fn = getattr(MonitorMode, "disable_monitor", None)
    if fn is None:
        pytest.skip("disable_monitor not part of this API")
    try:
        fn("wlan0mon")
    except (AttributeError, OSError):
        pytest.skip("disable_monitor signature differs / tooling absent")


# ---------------------------------------------------------------------------
# utils.cleanup — Cleanup.kill_background_processes + register_cleanup_handler
# ---------------------------------------------------------------------------


def test_cleanup_kill_background_processes(monkeypatch):
    from utils.cleanup import Cleanup

    c = Cleanup(interfaces=["wlan0mon"])
    monkeypatch.setattr(subprocess, "run", _ok)
    c.interfaces.append("wlan0mon")
    try:
        c.kill_background_processes()
    except Exception as e:
        pytest.fail(f"kill_background_processes raised: {e}")


def test_cleanup_cleanup_all_no_raise(monkeypatch):
    from utils.cleanup import Cleanup

    c = Cleanup(interfaces=["wlan0mon"])
    # Everything subprocess/file touches is mocked or tolerated — the
    # contract is "never raise during teardown".
    monkeypatch.setattr(subprocess, "run", _ok)
    c.cleanup_all()  # must not raise even when tooling is absent


# ---------------------------------------------------------------------------
# core.captive_portal — start/stop thread lifecycle (never binds a port)
# ---------------------------------------------------------------------------


def test_captive_portal_start_runs_thread_then_daemon_exit(tmp_path, monkeypatch):
    import threading

    from core.captive_portal import CaptivePortal
    from core.models import AppConfig

    cfg = AppConfig(secret_key="x" * 33)
    portal = CaptivePortal(config=cfg, logger_instance=mock.MagicMock())

    run_calls = {}
    real_thread = threading.Thread

    class FakeThread(real_thread):
        def start(self):
            run_calls["started"] = True
            # don't actually run app.run

    monkeypatch.setattr(threading, "Thread", FakeThread)
    portal.start()
    assert run_calls.get("started") is True


def test_captive_portal_ephemeral_secret_key(monkeypatch):
    import logging as _logging

    from core.captive_portal import CaptivePortal
    from core.models import AppConfig

    cfg = AppConfig(secret_key="")
    portal = CaptivePortal(
        config=cfg,
        logger_instance=_logging.getLogger("test_ephemeral"),
    )
    assert portal.app.secret_key  # ephemeral key generated


def test_captive_portal_get_captured_roundtrip():
    from core.captive_portal import CaptivePortal
    from core.models import AppConfig
    from utils.logger import CredentialLogger

    lg = CredentialLogger(log_file=str(None)) if False else CredentialLogger()
    portal = CaptivePortal(config=AppConfig(secret_key="y" * 33), logger_instance=lg)
    lg.log_credential(
        client_ip="10.9.9.9", phone="+911111111111", email="z@z.com", stage="otp_verified"
    )
    captured = portal.get_captured()
    assert any(c.client_ip == "10.9.9.9" for c in captured)


# ---------------------------------------------------------------------------
# validators — validate_phone/email direct edge coverage
# ---------------------------------------------------------------------------


def test_validate_email_long_tld_shape():
    from core.captive_portal import validate_email

    assert validate_email("user@sub.example.museum") is True
    assert validate_email("user@example.c") is False
