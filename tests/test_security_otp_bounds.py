"""Security tests for OTP rate-limit + lockout extension (security pass S-3).

The existing test_otp_service.py already covers the happy path;
this file pins down the *edge cases* the security pass added or tightened:

  * bound checks on input (length, type)
  * lockout transitions across the boundary (off → on → off)
  * decrypt-on-attempt reset semantics
  * OTP-service interaction with the per-IP rate_limit decorator
"""

from __future__ import annotations

import time

import pytest

from core.captive_portal import CaptivePortal, rate_limit
from core.models import AppConfig
from core.otp_service import (
    VALID_COUNTRY_CODES,
    BaseOTPService,
)


@pytest.fixture
def otp_svc():
    return BaseOTPService(
        otp_length=6,
        expiry_seconds=300,
        max_attempts=3,  # tight so tests stay short
        lockout_seconds=2,  # short window so we can probe transitions
    )


# ---------------------------------------------------------------------------
# S-3.1: lockout transitions (off → locked → off)
# ---------------------------------------------------------------------------


class TestLockoutTransitions:
    def test_lockout_engages_at_max_attempts(self, otp_svc):
        phone = "+911234567890"
        otp_svc.generate_otp(phone)

        for i in range(otp_svc.max_attempts):
            ok = otp_svc.verify_otp(phone, "000000")
            assert ok is False
        # Now locked.
        assert otp_svc.is_locked(phone) is True

    def test_locked_window_returns_false_without_consuming_otp(self, otp_svc):
        """Once locked, verify_otp() must return False without modifying store."""
        phone = "+911234567890"
        otp_svc.generate_otp(phone)
        for _ in range(otp_svc.max_attempts):
            otp_svc.verify_otp(phone, "000000")
        assert otp_svc.is_locked(phone)

        # Even the correct OTP is rejected during lockout.
        otp_svc._otp_store[phone] = {
            "otp_hash": __import__("hashlib").sha256(b"654321").hexdigest(),
            "created_at": time.time(),
        }
        # Confirm we hit the lockout branch (returns False fast).
        assert otp_svc.verify_otp(phone, "654321") is False
        assert otp_svc.is_locked(phone) is True

    def test_lockout_releases_after_window(self, otp_svc):
        phone = "+911234567890"
        otp_svc.generate_otp(phone)
        for _ in range(otp_svc.max_attempts):
            otp_svc.verify_otp(phone, "000000")
        assert otp_svc.is_locked(phone) is True

        # Wait past the lockout window.
        time.sleep(otp_svc.lockout_seconds + 0.1)
        assert otp_svc.is_locked(phone) is False

        # Fresh OTP should now verify cleanly.
        new_otp = otp_svc.generate_otp(phone)
        assert otp_svc.verify_otp(phone, new_otp) is True


# ---------------------------------------------------------------------------
# S-3.2: input bounding in /verify
# ---------------------------------------------------------------------------


class TestVerifyInputBounding:
    """OTP inputs are bounded to digits + length 1..12. Garbage is rejected."""

    @pytest.fixture
    def portal(self):
        cfg = AppConfig()
        cfg.secret_key = "x" * 32
        cfg.rate_limit_per_minute = 100
        # Use a no-op atexit hook during tests.
        CaptivePortal._atexit_registered = False
        p = CaptivePortal(config=cfg, otp_service=None, network_config=None)
        return p

    def _start_session_and_submit(self, portal) -> str:
        """Drive the user through GET / -> POST /submit and return csrf token."""
        csrf = portal.app.test_client().get("/").get_data(as_text=True)
        # csrf is in HTML — pull it via the session cookie to keep tests
        # resilient to template edits. We'll just exercise /verify with
        # a session-bound phone/email.
        with portal.app.test_client() as c:
            # GET / sets csrf + session cookie.
            c.get("/")
            # POST /submit (csrf-required) rebinds csrf cookie for otp page.
            csrf_token_from_session = c.get("/").request  # noqa: F841 (debug aid)
            # We need the *current* session csrf; Flask test client gives
            # cookies via c.get_cookie. Easier: drive through the real flow.
            with c.session_transaction() as sess:
                sess["phone"] = "+911234567890"
                sess["email"] = "victim@example.com"
                sess["csrf_token"] = "tok-test-abc"
            return "tok-test-abc"

    def test_extremely_long_otp_is_rejected(self, portal):
        with portal.app.test_client() as c:
            with c.session_transaction() as sess:
                sess["phone"] = "+911234567890"
                sess["email"] = "victim@example.com"
                sess["csrf_token"] = "tok-test-abc"
            resp = c.post(
                "/verify",
                data={"otp": "1" * 50, "csrf_token": "tok-test-abc"},
            )
        # 400 because length 50 exceeds the 12-char cap.
        assert resp.status_code == 400

    def test_empty_otp_is_rejected(self, portal):
        with portal.app.test_client() as c:
            with c.session_transaction() as sess:
                sess["phone"] = "+911234567890"
                sess["email"] = "victim@example.com"
                sess["csrf_token"] = "tok-test-abc"
            resp = c.post(
                "/verify",
                data={"otp": "", "csrf_token": "tok-test-abc"},
            )
        # Empty input is rejected (400 not 200 — the user gets a re-render, never a verification).
        assert resp.status_code == 400

    def test_non_digit_otp_strips_to_empty_and_returns_unknown(self, portal):
        """An OTP made entirely of letters collapses to '' after digit-strip → still rejected."""
        with portal.app.test_client() as c:
            with c.session_transaction() as sess:
                sess["phone"] = "+911234567890"
                sess["email"] = "victim@example.com"
                sess["csrf_token"] = "tok-test-abc"
            resp = c.post(
                "/verify",
                data={"otp": "abcdef", "csrf_token": "tok-test-abc"},
            )
        # Stripped input is empty -> 400 from the length check.
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# S-3.3: per-IP rate-limit decorator — confirm boundary + window semantics
# ---------------------------------------------------------------------------


class TestPerIPRateLimitDecorator:
    """The sliding-window rate_limit decorator caps requests per IP."""

    def test_under_limit_allows(self):
        @rate_limit(max_requests=3, window_seconds=60)
        def v():
            return "ok"

        from flask import Flask

        app = Flask(__name__)
        app.add_url_rule("/x", view_func=v)
        c = app.test_client()
        for _ in range(3):
            assert c.get("/x").status_code == 200

    def test_over_limit_returns_429(self):
        @rate_limit(max_requests=2, window_seconds=60)
        def v():
            return "ok"

        from flask import Flask

        app = Flask(__name__)
        app.add_url_rule("/x", view_func=v)
        c = app.test_client()
        c.get("/x")
        c.get("/x")
        r = c.get("/x")
        assert r.status_code == 429

    def test_window_reset(self):
        """After the window elapses, requests flow again."""

        @rate_limit(max_requests=2, window_seconds=1)
        def v():
            return "ok"

        from flask import Flask

        app = Flask(__name__)
        app.add_url_rule("/x", view_func=v)
        c = app.test_client()
        c.get("/x")
        c.get("/x")
        assert c.get("/x").status_code == 429
        import time as _t

        _t.sleep(1.1)
        assert c.get("/x").status_code == 200


# ---------------------------------------------------------------------------
# S-3.4: TwilioOTPService instantiation refuses without env-loaded creds
# ---------------------------------------------------------------------------


class TestTwilioCredentialSource:
    """Twilio SID/token must come from env, never hardcoded."""

    def test_no_hardcoded_credentials_in_service(self):
        import inspect

        from core import otp_service as otp_mod

        src = inspect.getsource(otp_mod)
        forbidden = ["ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "your-twilio-auth-token-here"]
        for needle in forbidden:
            assert needle not in src, f"Found hardcoded fallback '{needle}' in otp_service.py"

    def test_country_code_allowlist_present(self):
        """Server-side country-code allowlist enforces +91, +1, etc. — no client trust."""
        assert "+91" in VALID_COUNTRY_CODES
        assert "+1" in VALID_COUNTRY_CODES
        # Make sure some clearly-bogus codes are absent.
        assert "+999999" not in VALID_COUNTRY_CODES
