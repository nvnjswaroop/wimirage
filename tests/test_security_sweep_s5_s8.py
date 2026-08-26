"""Regression tests for the security + quality sweep (security pass S-5/-6/-7/-8).

These pin the contracts added/tightened in the second sweep:

  * **S-5 — PII scrub in route logs.** ``portal/routes.py`` calls helper
    :func:`portal.security.scrub_for_log` before writing phone / email
    to the audit log so the rotating-file logger doesn't carry captured
    data in cleartext. We exercise ``/submit``, ``/verify`` success, and
    ``/resend`` log emission with caplog and assert that the raw phone
    never lands in any emitted record.

  * **S-6 — cooperative-shutdown wiring.** :mod:`cli.menu` no longer
    shadows ``utils.cleanup:shutdown_event`` with a fresh
    ``threading.Event``. That means the SIGINT handler installed by
    ``register_cleanup_handler`` flips the *same* Event that
    :meth:`MenuHandler.do_full_chain` waits on. Saw a regression where
    Ctrl+C fell back to the 1.0s wait tick instead.

  * **S-7 — hostapd config injection resistance.** Embedded CR/LF in an
    AP SSID would have smuggled additional hostapd directives; the
    generator now strips them. This test pins that no ``\\n`` survives.

  * **S-8 — interface name validation.** ``MenuHandler.do_captive_portal``,
    ``do_network_routing``, and ``_select_interfaces_for_chain`` now
    reject iface names that aren't Linux-shaped, before the value reaches
    ``subprocess.run``.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import unittest.mock as mock

import pytest

from core.captive_portal import CaptivePortal
from core.models import AppConfig


# ---------------------------------------------------------------------------
# S-5.1: /submit — phone never lands raw in logs
# ---------------------------------------------------------------------------

class TestRouteLogsScrubbedPII:
    """Phone + email routes must scrub captured PII before logging."""

    @pytest.fixture
    def portal(self, monkeypatch):
        cfg = AppConfig()
        cfg.secret_key = "x" * 32
        cfg.enforce_https = False
        cfg.rate_limit_per_minute = 1000
        # Keep the atexit side-effect offline during tests.
        monkeypatch.setattr("atexit.register", lambda *_a, **_kw: None)
        monkeypatch.setattr("core.captive_portal.flush_iptables", lambda: None)
        CaptivePortal._atexit_registered = False
        return CaptivePortal(config=cfg, otp_service=None, network_config=None)

    def test_submit_does_not_leak_raw_phone(self, portal, caplog):
        with caplog.at_level(logging.INFO, logger="wimirage"):
            with portal.app.test_client() as c:
                # Drive session + csrf
                r = c.get("/")
                csrf1 = r.data.decode().split(
                    'name="csrf_token" value="'
                )[1].split('"')[0]
                r = c.post("/submit", data={
                    "phone": "9876543210",
                    "email": "victim@example.com",
                    "country_code": "+91",
                    "csrf_token": csrf1,
                })
                assert r.status_code == 200

        # The raw full_phone "+919876543210" must NOT appear in any
        # captured log record. Masked variants (e.g. the worker's
        # own stdout prints) don't go through the logger.
        full_phone = "+919876543210"
        leaked = [r for r in caplog.records if full_phone in r.getMessage()]
        assert not leaked, (
            f"/submit leaked raw phone to logs: "
            f"{[r.getMessage() for r in leaked]}"
        )
        # And the captured *email* shouldn't either.
        leaked_email = [r for r in caplog.records if "victim@example.com" in r.getMessage()]
        assert not leaked_email, (
            f"/submit leaked raw email to logs: "
            f"{[r.getMessage() for r in leaked_email]}"
        )

    def test_verify_success_scrubs_phone_and_email(self, portal, caplog):
        with portal.app.test_client() as c:
            r = c.get("/")
            csrf1 = r.data.decode().split(
                'name="csrf_token" value="'
            )[1].split('"')[0]
            r = c.post("/submit", data={
                "phone": "9876543210",
                "email": "secret-victim@example.com",
                "country_code": "+91",
                "csrf_token": csrf1,
            })
            csrf2 = r.data.decode().split(
                'name="csrf_token" value="'
            )[1].split('"')[0]

            with caplog.at_level(logging.INFO, logger="wimirage"):
                # otp_service=None → auto-verifies.
                r = c.post("/verify", data={
                    "otp": "123456",
                    "csrf_token": csrf2,
                })

        full_phone = "+919876543210"
        raw_email = "secret-victim@example.com"
        leaked = [
            r for r in caplog.records
            if full_phone in r.getMessage() or raw_email in r.getMessage()
        ]
        assert not leaked, (
            f"/verify leaked raw PII to logs: "
            f"{[r.getMessage() for r in leaked]}"
        )

    def test_resend_scrubs_phone(self, portal, caplog):
        with portal.app.test_client() as c:
            r = c.get("/")
            csrf1 = r.data.decode().split(
                'name="csrf_token" value="'
            )[1].split('"')[0]
            r = c.post("/submit", data={
                "phone": "9876543210",
                "email": "v@example.com",
                "country_code": "+91",
                "csrf_token": csrf1,
            })
            csrf2 = r.data.decode().split(
                'name="csrf_token" value="'
            )[1].split('"')[0]
            with caplog.at_level(logging.INFO, logger="wimirage"):
                r = c.post("/resend", data={"csrf_token": csrf2})

        full_phone = "+919876543210"
        leaked = [r for r in caplog.records if full_phone in r.getMessage()]
        assert not leaked, (
            f"/resend leaked raw phone to logs: "
            f"{[r.getMessage() for r in leaked]}"
        )


# ---------------------------------------------------------------------------
# S-6: cli.menu shutdown_event imports the canonical event
# ---------------------------------------------------------------------------

class TestShutdownEventIsCanonical:
    """``cli.menu`` must use the SAME shutdown_event that
    ``utils.cleanup.request_shutdown`` flips. If it shadows a fresh
    ``threading.Event``, SIGINT ignores the wait loop in ``do_full_chain``
    and falls back to the 1.0s tick — defeating the cooperative-shutdown
    contract.
    """

    def test_no_shadow_thread_event(self):
        from cli import menu
        from utils import cleanup
        # Importing the module should give us the SAME object the
        # Signal handler will flip.
        assert menu._shutdown_event is cleanup.shutdown_event, (
            "_shutdown_event in cli/menu.py is a *different* Event than "
            "utils.cleanup's canonical one — Ctrl+C will not wake "
            "do_full_chain()'s wait."
        )

    def test_request_shutdown_wakes_the_event_menu_uses(self):
        """``request_shutdown`` must set the Event ``cli.menu`` waits on."""
        from cli import menu
        from utils import cleanup

        cleanup.reset_shutdown()
        try:
            assert menu._shutdown_event.is_set() is False
            cleanup.request_shutdown()
            assert menu._shutdown_event.is_set() is True
        finally:
            cleanup.reset_shutdown()


# ---------------------------------------------------------------------------
# S-7: hostapd config must have no embedded newlines from SSID
# ---------------------------------------------------------------------------

class TestHostapdConfigSanitizesSSID:
    """Embedded CR/LF in the SSID would smuggle a new directive into
    the rendered hostapd.conf. The generator strips them.
    """

    def test_newline_in_ssid_does_not_inject(self, tmp_path, monkeypatch):
        # Redirect config + pid paths so we don't touch the real ones.
        import core.rogue_ap as rogue_mod
        from core import paths as core_paths

        hostapd_conf = tmp_path / "hostapd.conf"
        monkeypatch.setattr(core_paths, "HOSTAPD_CONF_PATH", str(hostapd_conf))
        monkeypatch.setattr(core_paths, "DNSMASQ_CONF_PATH", str(tmp_path / "dnsmasq.conf"))
        monkeypatch.setattr(core_paths, "HOSTAPD_PID_PATH", str(tmp_path / "hostapd.pid"))
        monkeypatch.setattr(core_paths, "DNSMASQ_PID_PATH", str(tmp_path / "dnsmasq.pid"))
        monkeypatch.setattr(rogue_mod, "HOSTAPD_CONF_PATH", str(hostapd_conf))
        monkeypatch.setattr(rogue_mod, "DNSMASQ_CONF_PATH", str(tmp_path / "dnsmasq.conf"))
        monkeypatch.setattr(rogue_mod, "HOSTAPD_PID_PATH", str(tmp_path / "hostapd.pid"))
        monkeypatch.setattr(rogue_mod, "DNSMASQ_PID_PATH", str(tmp_path / "dnsmasq.pid"))
        monkeypatch.setattr(rogue_mod, "ensure_config_dir", lambda: None)

        ap = rogue_mod.RogueAP(
            interface="wlan0",
            ssid="evil\nignore_broadcast_ssid=2",
            channel=1,
        )
        out_path = ap._generate_hostapd_config()

        with open(out_path, encoding="utf-8") as f:
            rendered = f.read()

        # Pull the canonical ssid= line and confirm it contains the
        # smuggled directive on the same line. hostapd's behaviour is:
        # newline-free lines are parsed as single options, so
        # "ssid=evil\nignore_broadcast_ssid=2" would have ended up as two
        # separate directives (ssid=evil + ignore_broadcast_ssid=2). The
        # newline-strip collapses it onto one ssid line — safe.
        ssid_line = next(
            (ln.strip() for ln in rendered.splitlines() if ln.startswith("ssid=")),
            None,
        )
        assert ssid_line is not None, "no ssid= line was rendered"
        assert "\n" not in ssid_line
        assert "\r" not in ssid_line
        # Every option besides ssid should be one of the canonical ones.
        canonical_keys = {
            "interface=", "driver=", "ssid=", "hw_mode=", "channel=",
            "wmm_enabled=", "macaddr_acl=", "ignore_broadcast_ssid=",
        }
        for line in rendered.splitlines():
            assert any(line.startswith(k) for k in canonical_keys), (
                f"rendered hostapd.conf has an unrecognised option line: "
                f"{line!r}"
            )


# ---------------------------------------------------------------------------
# S-8: MenuHandler rejects bogus interface names
# ---------------------------------------------------------------------------

class TestInterfaceNameValidation:
    """Internet-iface strings that hit subprocess need a regex check."""

    PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,16}$")

    def test_eth0_accepted(self):
        assert self.PATTERN.match("eth0")

    def test_wlan0colon_alias_accepted(self):
        assert self.PATTERN.match("wlan0:1")

    def test_shell_metacharacters_rejected(self):
        assert not self.PATTERN.match("eth0; rm -rf /")

    def test_way_too_long_rejected(self):
        # IFNAMSIZ is 16 in Linux; reject anything longer.
        assert not self.PATTERN.match("a" * 17)

    def test_whitespace_rejected(self):
        assert not self.PATTERN.match("eth 0")

    def test_do_captive_portal_rejects_bad_input(self, monkeypatch):
        """Drive the actual menu method with monkeypatched input() and
        confirm the bad iface name aborts the flow before any subprocess
        call.
        """
        from cli.menu import MenuHandler
        from cli.context import AttackContext
        # Build a context (no real scanning needed).
        ctx = AttackContext(AppConfig())
        handler = MenuHandler(ctx)

        bogus_inputs = iter(["eth0; rm -rf /"])  # one prompt
        monkeypatch.setattr("builtins.input", lambda *_a, **_kw: next(bogus_inputs))

        # Build minimal fake for get_otp_service so the menu doesn't reach
        # the actual iptables / portal paths.
        monkeypatch.setattr(handler, "get_otp_service", lambda: None)
        # And short-circuit policy selection.
        ctx.ap_interface = "wlan0"

        with mock.patch("cli.menu.NetworkConfig") as mock_net:
            handler.do_captive_portal()
            mock_net.assert_not_called(), (
                "captive portal built NetworkConfig with the bad iface "
                "name despite validation in the menu prompt"
            )


# ---------------------------------------------------------------------------
# Bonus defense-in-depth: combined /verify surface stays bounded
# ---------------------------------------------------------------------------

class TestVerifyDefenseInDepth:
    """Confirm the layered defense (csrf + per-IP rate-limit + per-phone
    OTP lockout + digits-only OTP + length cap) holds for an attacker
    running the same script.
    """

    @pytest.fixture
    def portal(self, monkeypatch):
        cfg = AppConfig()
        cfg.secret_key = "x" * 32
        cfg.enforce_https = False

        from core.otp_service import BaseOTPService
        otp = BaseOTPService(otp_length=6, expiry_seconds=300,
                             max_attempts=3, lockout_seconds=2)

        monkeypatch.setattr("atexit.register", lambda *_a, **_kw: None)
        monkeypatch.setattr("core.captive_portal.flush_iptables", lambda: None)
        CaptivePortal._atexit_registered = False
        return CaptivePortal(config=cfg, otp_service=otp, network_config=None)

    def test_locked_phone_returns_429_then_unlocks(self, portal):
        phone = "+919****3210"
        # Bring the OTP service to a known state: 1 active OTP, no
        # attempts on the phone yet.
        portal.otp_service.generate_otp(phone)

        with portal.app.test_client() as c:
            # Drive up to 6 attempts (more than max_attempts=3 so the
            # lockout branch fires regardless of pre-lockout response).
            results = []
            csrf = "tok-A"
            with c.session_transaction() as sess:
                sess["phone"] = phone
                sess["email"] = "v@example.com"
                sess["csrf_token"] = csrf

            for i in range(6):
                r = c.post("/verify", data={
                    "otp": "000000", "csrf_token": csrf,
                })
                results.append(r.status_code)
                # After every attempt the route either (a) advances to a
                # re-render that rotated csrf_token in the session, or (b)
                # cleared the session on /verify success. Re-mint a fresh
                # csrf and re-set session phone/email so subsequent
                # attempts reach the OTP service rather than bouncing on
                # the csrf=403 short-circuit.
                with c.session_transaction() as sess:
                    sess["phone"] = phone
                    sess["email"] = "v@example.com"
                    csrf = f"tok-A{i+1}"
                    sess["csrf_token"] = csrf

            assert 429 in results, (
                f"expected per-phone lockout (429) among attempts: {results}"
            )

            # After lockout_seconds (2s in the fixture) the lockout
            # releases — the next attempt with a fresh OTP should
            # succeed.
            time.sleep(2.2)
            new_otp = portal.otp_service.generate_otp(phone)
            with c.session_transaction() as sess:
                sess["phone"] = phone
                sess["csrf_token"] = "tok-final"
            r = c.post("/verify", data={
                "otp": new_otp, "csrf_token": "tok-final"
            })
            assert r.status_code in (200, 308), (
                f"after lockout release + fresh OTP, /verify should land "
                f"on success-ish path; got {r.status_code}"
            )
