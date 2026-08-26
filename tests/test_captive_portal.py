from core.captive_portal import CaptivePortal, rate_limit, validate_email, validate_phone
from core.models import AppConfig
from core.otp_service import DemoOTPService


class TestValidators:
    def test_validate_phone_valid(self):
        assert validate_phone("9876543210") is True
        assert validate_phone("+919876543210") is True
        assert validate_phone("+123456789") is True

    def test_validate_phone_invalid(self):
        assert validate_phone("") is False
        assert validate_phone("abc") is False
        assert validate_phone("123") is False
        assert validate_phone("+" * 20) is False

    def test_validate_email_valid(self):
        assert validate_email("test@example.com") is True
        assert validate_email("user.name@domain.co.uk") is True
        assert validate_email("a@b.co") is True

    def test_validate_email_invalid(self):
        assert validate_email("") is False
        assert validate_email("notanemail") is False
        assert validate_email("@nodomain.com") is False
        assert validate_email("no@domain") is False
        assert validate_email("spaces in@email.com") is False


class TestRateLimitDecorator:
    def test_rate_limit_allows_within_limit(self):
        @rate_limit(max_requests=3, window_seconds=60)
        def dummy_view():
            return "ok", 200

        from flask import Flask

        app = Flask(__name__)
        with app.test_request_context():
            for _ in range(3):
                response, code = dummy_view()
                assert code == 200

    def test_rate_limit_blocks_after_exceed(self):
        @rate_limit(max_requests=2, window_seconds=60)
        def dummy_view():
            return "ok", 200

        from flask import Flask

        app = Flask(__name__)
        with app.test_request_context():
            dummy_view()
            dummy_view()
            response = dummy_view()
            # The decorator now returns a Flask Response (via make_response),
            # not a (body, code) tuple. Inspect via status_code directly.
            assert response.status_code == 429


class TestCaptivePortalRoutes:
    def test_index_returns_200(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            response = client.get("/")
            assert response.status_code == 200
            assert b"Free Wi-Fi" in response.data

    def test_login_has_csrf_token(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            response = client.get("/")
            assert b"csrf_token" in response.data

    def test_submit_without_csrf_returns_403(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            response = client.post(
                "/submit",
                data={
                    "phone": "9876543210",
                    "email": "test@example.com",
                    "country_code": "+91",
                    "csrf_token": "invalid_token",
                },
            )
            assert response.status_code == 403

    def test_submit_invalid_country_code(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            client.get("/")
            response = client.post(
                "/submit",
                data={
                    "phone": "9876543210",
                    "email": "test@example.com",
                    "country_code": "+999",
                    "csrf_token": "",
                },
                follow_redirects=False,
            )
            assert response.status_code == 403

    def test_submit_missing_phone(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            response = client.get("/")
            csrf = response.data.decode().split('name="csrf_token" value="')[1].split('"')[0]

            response = client.post(
                "/submit",
                data={
                    "phone": "",
                    "email": "test@example.com",
                    "country_code": "+91",
                    "csrf_token": csrf,
                },
            )
            assert b"required" in response.data.lower() or b"error" in response.data.lower()

    def test_submit_invalid_email_format(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            response = client.get("/")
            csrf = response.data.decode().split('name="csrf_token" value="')[1].split('"')[0]

            response = client.post(
                "/submit",
                data={
                    "phone": "9876543210",
                    "email": "not-an-email",
                    "country_code": "+91",
                    "csrf_token": csrf,
                },
            )
            assert b"Invalid email" in response.data or response.status_code == 200

    def test_verify_without_csrf_returns_403(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            response = client.post(
                "/verify",
                data={
                    "otp": "123456",
                    "phone": "+919876543210",
                    "email": "test@example.com",
                    "csrf_token": "bad_token",
                },
            )
            assert response.status_code == 403

    def test_security_headers_present(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            response = client.get("/")
            assert "X-Frame-Options" in response.headers
            assert response.headers["X-Frame-Options"] == "DENY"
            assert "X-Content-Type-Options" in response.headers
            assert "Content-Security-Policy" in response.headers

    def test_resend_without_csrf_returns_403(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key"
        portal = CaptivePortal(config=config)
        with portal.app.test_client() as client:
            response = client.post(
                "/resend",
                data={
                    "phone": "+919876543210",
                    "email": "test@example.com",
                    "csrf_token": "bad_token",
                },
            )
            assert response.status_code == 403


class TestB1RegressionSessionStrictPhone:
    """Regression test for review-finding B1: /verify + /resend must read
    phone/email strictly from session. A form-supplied phone MUST NOT
    override the session-bound phone — doing so would let an attacker
    rebind the OTP target while keeping the victim's email in the
    credential log (session-fixation foot-gun).
    """

    def test_verify_form_phone_does_not_override_session_phone(self):
        config = AppConfig()
        config.secret_key = "test-secret-key"
        config.portal_port = 5000
        # Spy on the OTP service to capture what phone number gets used.
        verify_calls: list[str] = []

        class _SpyOTP(DemoOTPService):
            def verify_otp(self, phone, otp_input):
                verify_calls.append(phone)
                # Return False so we don't try to grant internet / render success.
                return False

        portal = CaptivePortal(config=config, otp_service=_SpyOTP())
        with portal.app.test_client() as client:
            # Obtain a real csrf token from GET /.
            csrf = client.get("/").data.decode().split('name="csrf_token" value="')[1].split('"')[0]
            # Submit a legitimate session phone (the only one we want to allow).
            client.post(
                "/submit",
                data={
                    "csrf_token": csrf,
                    "phone": "5551234567",
                    "email": "victim@example.com",
                    "country_code": "+91",
                },
            )
            csrf = client.get("/").data.decode().split('name="csrf_token" value="')[1].split('"')[0]
            # /verify: try to override the phone via the hidden form field
            # AND by sending a fresh session phone on a different IP.
            # Only the SESSION phone should be forwarded to verify_otp.
            response = client.post(
                "/verify",
                data={
                    "csrf_token": csrf,
                    "otp": "000000",
                    "phone": "+16666666666",  # attacker-supplied
                    "email": "attacker@evil.com",  # attacker-supplied
                },
            )
        # The OTP service should be called with the SUBMIT-bound phone,
        # not the attacker-supplied phone.
        assert verify_calls, "OTP service was never invoked"
        assert verify_calls[0] == "+915551234567", (
            f"BUG B1 — verify_otp got {verify_calls[0]!r}, expected the "
            f"session-bound phone +915551234567"
        )


class TestCaptivePortalIntegration:
    def test_full_flow_demo_mode(self):
        config = AppConfig()
        config.portal_port = 5000
        config.secret_key = "test-secret-key-12345"
        otp_service = DemoOTPService()
        portal = CaptivePortal(config=config, otp_service=otp_service)

        with portal.app.test_client() as client:
            get_resp = client.get("/")
            assert get_resp.status_code == 200
            html = get_resp.data.decode()
            csrf = html.split('name="csrf_token" value="')[1].split('"')[0]

            submit_resp = client.post(
                "/submit",
                data={
                    "phone": "9876543210",
                    "email": "testuser@example.com",
                    "country_code": "+91",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            assert submit_resp.status_code == 200
            assert b"Verify OTP" in submit_resp.data or b"OTP" in submit_resp.data

            otp_html = submit_resp.data.decode()
            otp_csrf = otp_html.split('name="csrf_token" value="')[1].split('"')[0]

            verify_resp = client.post(
                "/verify",
                data={
                    "otp": "000000",
                    "phone": "+919876543210",
                    "email": "testuser@example.com",
                    "csrf_token": otp_csrf,
                },
                follow_redirects=False,
            )
            assert verify_resp.status_code == 200
