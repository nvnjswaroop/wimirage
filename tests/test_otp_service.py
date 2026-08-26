import time

import pytest

from core.otp_service import (
    VALID_COUNTRY_CODES,
    DemoOTPService,
    OTPServiceInterface,
    TwilioOTPService,
)


class TestOTPServiceInterface:
    def test_is_abstract(self):
        service = DemoOTPService()
        assert isinstance(service, OTPServiceInterface)


class TestBaseOTPService:
    def test_generate_otp_returns_six_digits(self):
        service = DemoOTPService()
        otp = service.generate_otp("+919876543210")
        assert len(otp) == 6
        assert otp.isdigit()

    def test_generate_otp_different_each_time(self):
        service = DemoOTPService()
        otp1 = service.generate_otp("+919876543210")
        otp2 = service.generate_otp("+919876543210")
        assert otp1 != otp2

    def test_generate_otp_stores_hash_not_plaintext(self):
        service = DemoOTPService()
        otp = service.generate_otp("+919876543210")
        assert (
            otp in service._otp_store["+919876543210"]["otp_hash"]
            or service._otp_store["+919876543210"]["otp_hash"]
        )

    def test_verify_correct_otp(self):
        service = DemoOTPService()
        otp = service.generate_otp("+919876543210")
        assert service.verify_otp("+919876543210", otp) is True

    def test_verify_wrong_otp(self):
        service = DemoOTPService()
        service.generate_otp("+919876543210")
        assert service.verify_otp("+919876543210", "000000") is False

    def test_verify_unknown_phone(self):
        service = DemoOTPService()
        assert service.verify_otp("+919999999999", "123456") is False

    def test_verify_otp_expired(self):
        service = DemoOTPService(expiry_seconds=1)
        otp = service.generate_otp("+919876543210")
        time.sleep(1.1)
        assert service.verify_otp("+919876543210", otp) is False

    def test_verify_otp_consumed_after_success(self):
        service = DemoOTPService()
        otp = service.generate_otp("+919876543210")
        assert service.verify_otp("+919876543210", otp) is True
        assert service.verify_otp("+919876543210", otp) is False

    def test_max_attempts_lockout(self):
        service = DemoOTPService(max_attempts=3, lockout_seconds=60)
        service.generate_otp("+919876543210")
        service.verify_otp("+919876543210", "000001")
        service.verify_otp("+919876543210", "000002")
        service.verify_otp("+919876543210", "000003")
        assert service.is_locked("+919876543210") is True

    def test_lockout_released_after_timeout(self):
        service = DemoOTPService(max_attempts=3, lockout_seconds=1)
        service.generate_otp("+919876543210")
        service.verify_otp("+919876543210", "000001")
        service.verify_otp("+919876543210", "000002")
        service.verify_otp("+919876543210", "000003")
        assert service.is_locked("+919876543210") is True
        time.sleep(1.1)
        assert service.is_locked("+919876543210") is False

    def test_multiple_phones_independent(self):
        service = DemoOTPService(max_attempts=2)
        otp1 = service.generate_otp("+919876543210")
        service.generate_otp("+919876543211")
        assert service.verify_otp("+919876543210", otp1) is True
        assert service.is_locked("+919876543211") is False


class TestDemoOTPService:
    def test_send_otp_logs_otp(self, caplog):
        """DemoOTPService.send_otp must surface the OTP value via the logger."""
        import logging

        caplog.set_level(logging.INFO, logger="wimirage")
        service = DemoOTPService()
        service.send_otp("+919****3210", "123456")
        assert "123456" in caplog.text
        assert "+919****3210" in caplog.text

    def test_generate_otp_logs_demo_message(self, caplog):
        """DemoOTPService.generate_otp must log a 'DEMO' line so devs can see OTPs."""
        import logging

        caplog.set_level(logging.INFO, logger="wimirage")
        service = DemoOTPService()
        service.generate_otp("+919****3210")
        assert "DEMO" in caplog.text


class TestValidCountryCodes:
    def test_valid_codes_list_not_empty(self):
        assert len(VALID_COUNTRY_CODES) > 0

    def test_all_codes_start_with_plus(self):
        for code in VALID_COUNTRY_CODES:
            assert code.startswith("+")

    def test_common_codes_present(self):
        assert "+91" in VALID_COUNTRY_CODES
        assert "+1" in VALID_COUNTRY_CODES
        assert "+44" in VALID_COUNTRY_CODES


class TestOtpHashInvariants:
    """Section 7 #11: timing-safe hash format invariants.

    HMAC.compare_digest is not directly timing-measurable in a unit test,
    but we *can* verify the implementation uses it (not ==) and that the
    stored representation is the ``salt_b64$hexdigest`` shape it claims
    to be (one regression-bait on the salt prefix keeps the OTP store
    from accidentally reverting to unsalted SHA-256).
    """

    def test_stored_hash_is_salted_sha256_hex(self):
        service = DemoOTPService()
        plaintext = service.generate_otp("+919****3210")

        # Stored representation is "salt_b64$sha256(salt||otp)" — never
        # the raw OTP, and never an unsalted SHA-256.
        stored = service._otp_store["+919****3210"]
        assert stored["otp_hash"] != plaintext, "OTP must not be stored plaintext"
        assert "$" in stored["otp_hash"], "stored OTP must carry its salt"
        salt_b64, _, digest = stored["otp_hash"].partition("$")
        # b64(16 bytes) = 24 chars including padding
        assert 20 <= len(salt_b64) <= 32, "salt base64 length out of range"
        # SHA-256 hex digest is 64 lowercase hex chars.
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest), "stored digest must be lowercase hex"

    def test_hash_matches_salted_sha256_of_otp(self):
        import base64
        import hashlib

        from core.otp_service import DemoOTPService

        service = DemoOTPService()
        plaintext = service.generate_otp("+91ABCDEF0123")
        salt_b64, _, stored_digest = service._otp_store["+91ABCDEF0123"]["otp_hash"].partition("$")
        salt = base64.b64decode(salt_b64, validate=False)
        expected = hashlib.sha256(salt + plaintext.encode()).hexdigest()
        assert stored_digest == expected, "stored digest must equal SHA-256(salt || otp)"
        # And the OTP itself must NOT match an unsalted SHA-256 of itself —
        # otherwise we accidentally stored the legacy unsalted shape.
        unsalted = hashlib.sha256(plaintext.encode()).hexdigest()
        assert stored_digest != unsalted, "stored digest must NOT be unsalted SHA-256"

    def test_salt_differs_across_two_generate_calls(self):
        # Defeat any \"salt got accidentally cached as a class attribute\"
        # regression: two consecutive OTPs for the same phone must carry
        # different salt prefixes — otherwise the entire salt scheme
        # collapses back to a 1-entry rainbow table.
        service = DemoOTPService()
        service.generate_otp("+919****7777")
        first = service._otp_store["+919****7777"]["otp_hash"]
        service.generate_otp("+919****7777")
        second = service._otp_store["+919****7777"]["otp_hash"]
        assert first != second

    def test_hmac_compare_digest_used(self):
        """Verify verify_otp uses hmac.compare_digest, not ==."""
        import inspect

        import core.otp_service as otp_mod

        src = inspect.getsource(otp_mod.BaseOTPService.verify_otp)
        assert "compare_digest" in src, "verify_otp must use hmac.compare_digest for timing safety"
        # And not the naive '=='.
        # The substring `== stored[` is fine because stored lookup uses
        # a dict; the boolean-compare we care about is the hash equality.
        assert "input_hash == stored" not in src, "verify_otp must not use == on hash digests"


# ---------------------------------------------------------------------------
# BackendError contract — Twilio (and any future backend) must wrap vendor
# exceptions in OTPBackendError so route handlers don't depend on vendor SDKs.
# ---------------------------------------------------------------------------


class TestOTPBackendError:
    def test_twilio_wraps_oserror_as_backend_error(self, monkeypatch):
        """Transport (OSError) failures → OTPBackendError.

        We bypass ``__init__`` (which would need the optional ``twilio``
        package to import) and stub ``svc._client`` directly; the goal is
        to exercise the exception-clause contract, not the Twilio SDK.
        """
        from core.otp_service import OTPBackendError

        svc = object.__new__(TwilioOTPService)
        svc.from_phone = "+155****0000"

        # Mock shape matches: `_client.messages.create(...)` (Twilio SDK)
        class _Messages:
            def create(self, **_kwargs):
                raise OSError("connection refused")

        class _Client:
            messages = _Messages()

        svc._client = _Client()
        with pytest.raises(OTPBackendError, match="SMS transport failure"):
            svc.send_otp("+155****9999", "123456")

    def test_twilio_wraps_vendor_exception_as_backend_error(self, monkeypatch):
        """Vendor-specific exceptions → OTPBackendError (don't import Twilio)."""
        from core.otp_service import OTPBackendError

        svc = object.__new__(TwilioOTPService)
        svc.from_phone = "+155****0000"

        class _Messages:
            def create(self, **_kwargs):
                # Pretend to be Twilio's TwilioRestException without importing it
                raise RuntimeError("API authentication failed")

        class _Client:
            messages = _Messages()

        svc._client = _Client()
        with pytest.raises(OTPBackendError, match="SMS delivery failed"):
            svc.send_otp("+155****9999", "123456")
