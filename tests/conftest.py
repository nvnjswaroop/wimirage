import os
import re
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.models import AppConfig, AccessPoint, Credential


# Section 7 #3 — strip ANSI escape sequences from capsys output so test
# assertions are colour-blind.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mGKHJ]")


@pytest.fixture
def strip_ansi():
    """Return ``capsys.readouterr().out`` with ANSI codes removed."""
    def _strip(text: str) -> str:
        return _ANSI_RE.sub("", text)
    return _strip


@pytest.fixture
def tty_true(monkeypatch):
    """Pretend stdout is a TTY so loggers that branch on isatty() emit colour."""
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)


@pytest.fixture
def app_config():
    config = AppConfig()
    config.gateway = "10.0.0.1"
    config.dhcp_range = "10.0.0.2,10.0.0.100"
    config.portal_port = 8080
    config.scan_timeout = 5
    config.deauth_pps = 50
    config.otp_length = 6
    config.otp_expiry_seconds = 300
    config.otp_max_attempts = 5
    config.otp_lockout_seconds = 600
    config.rate_limit_per_minute = 10
    config.secret_key = "test-secret-key-12345"
    return config


@pytest.fixture
def sample_ap():
    return AccessPoint(
        ssid="TestNetwork",
        bssid="AA:BB:CC:DD:EE:FF",
        channel=6,
        signal=-45,
        encryption="WPA2",
        clients=["11:22:33:44:55:66"]
    )


@pytest.fixture
def sample_credential():
    return Credential(
        timestamp="2026-06-17 12:00:00",
        client_ip="10.0.0.25",
        phone="+919876543210",
        email="test@example.com",
        otp=None,
        stage="otp_verified"
    )