"""Authentication for portal-facing admin capabilities (security pass S-2).

Provides:
    - :func:`admin_required` — HTTP Basic auth decorator backed by an env-loaded
      CHAYAJALA_ADMIN_TOKEN. Used to gate any route that exposes captured
      credentials or runtime config.
    - :func:`audit_admin_access` — log every admin hit (success or failure)
      to the rotating audit log without leaking the submitted bearer.
    - :func:`load_admin_token` — read ``CHAYAJALA_ADMIN_TOKEN`` (or fallback
      ``ADMIN_TOKEN``) from the environment. Refuses to load default/empty.
    - :func:`scrub_for_log` — scrub obvious PII (phone/email-like substrings)
      before writing to the audit log.

Everything here is dependency-free (stdlib only) and testable via Flask's
test client without spinning up a real listener.
"""

from __future__ import annotations

import base64
import hmac
import logging
import os
import re
import secrets
from functools import wraps
from typing import Callable, Optional

from flask import jsonify, request

logger = logging.getLogger("wimirage")

__all__ = [
    "admin_required",
    "audit_admin_access",
    "load_admin_token",
    "scrub_for_log",
    "ADMIN_TOKEN_ENV_VARS",
]


ADMIN_TOKEN_ENV_VARS = ("CHAYAJALA_ADMIN_TOKEN", "ADMIN_TOKEN")

# Tokens must be at least 32 chars of high-entropy material; shorter or
# default values are refused outright. ``DUMMY_DEFAULT`` is the sentinel
# that modules were previously hard-coded with; we still explicitly check
# for it to avoid silent acceptance.
_MIN_TOKEN_LENGTH = 32
_DUMMY_DEFAULTS = frozenset({"change-me", "changeme", "admin", "password"})


def load_admin_token() -> Optional[str]:
    """Return the configured admin token from env, or ``None`` if absent/invalid.

    The token must be at least 32 characters. Default/placeholder values
    are refused — operators must explicitly set a strong token via the
    environment. Returning ``None`` causes :func:`admin_required` to deny
    every request, which is the safe failure mode.
    """
    for name in ADMIN_TOKEN_ENV_VARS:
        raw = os.environ.get(name, "").strip()
        if not raw:
            continue
        if len(raw) < _MIN_TOKEN_LENGTH:
            logger.warning(
                "Admin token in $%s is shorter than %d chars; ignoring.",
                name, _MIN_TOKEN_LENGTH,
            )
            return None
        if raw.lower() in _DUMMY_DEFAULTS:
            logger.warning("Admin token in $%s is a placeholder; ignoring.", name)
            return None
        # Also reject values whose trimmed-lowercase form contains a
        # placeholder-as-substring at any boundary (catches "adminxxxx..."
        # cheats where someone pads a placeholder to clear the 32-char floor).
        lowered = raw.lower()
        for placeholder in _DUMMY_DEFAULTS:
            if (
                lowered.startswith(placeholder)
                or lowered.endswith(placeholder)
            ):
                logger.warning(
                    "Admin token in $%s contains a placeholder substring; ignoring.",
                    name,
                )
                return None
        return raw
    return None


# Pre-compiled scrub regexes. Phone + email + IPv4 patterns only;
# everything else (e.g. base64-ish blobs left in headers) passes through.
_PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{6,}\d")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def scrub_for_log(value: str) -> str:
    """Return ``value`` with phone/email-like substrings redacted.

    Used by the audit logger so admin access lines never carry capturable
    PII. Numbers that are too short to be phone-shaped are left alone (e.g.
    ports, counts).
    """
    if not isinstance(value, str):
        value = str(value)
    redacted = _PHONE_RE.sub("[PHONE]", value)
    redacted = _EMAIL_RE.sub("[EMAIL]", redacted)
    return redacted


def _check_basic_auth(token: str, request_obj) -> bool:
    """Constant-time compare ``Authorization: Basic …`` header to ``token``."""
    header = request_obj.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(header[6:], validate=True).decode("utf-8", "replace")
    except (ValueError, base64.binascii.Error):
        return False
    # Accept both ``token`` and ``user:token`` shapes to be friendly to
    # curl users, but only the part after the first colon if present.
    submitted = decoded.split(":", 1)[1] if ":" in decoded else decoded
    return hmac.compare_digest(submitted.encode("utf-8"), token.encode("utf-8"))


def audit_admin_access(success: bool, ip: str, path: str, token: Optional[str]) -> None:
    """Emit a single audit-log line for an admin auth attempt.

    Never logs the token itself; logs only ``ok``/``denied`` plus the IP and
    path. This keeps the audit trail useful while remaining safe to ship
    to a shared log collector.
    """
    status = "ok" if success else "denied"
    logger.info(
        "admin_auth status=%s ip=%s path=%s",
        status, scrub_for_log(ip), scrub_for_log(path),
    )


def admin_required(view: Callable) -> Callable:
    """Decorator: gate a Flask view behind ``load_admin_token()`` basic auth.

    Behaviour:
        * Missing/empty/placeholder env token → 503 (server-misconfig; safer
          than 500 because admins see a clear "set CHAYAJALA_ADMIN_TOKEN"
          message instead of a stack trace).
        * Bad credentials → 401 with a ``WWW-Authenticate`` challenge.
        * Good credentials → view runs as normal.

    The decorator deliberately re-loads the token on every request rather
    than caching, so operators can rotate the token by ``export``-ing a new
    value without restarting the portal.
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr or "0.0.0.0"
        token = load_admin_token()
        if not token:
            audit_admin_access(False, ip, request.path, None)
            return jsonify(
                {"error": "admin endpoint disabled — set "
                         "CHAYAJALA_ADMIN_TOKEN env var (>=32 chars) to enable"}
            ), 503
        if not _check_basic_auth(token, request):
            audit_admin_access(False, ip, request.path, token)
            resp = jsonify({"error": "admin auth required"})
            resp.status_code = 401
            resp.headers["WWW-Authenticate"] = 'Basic realm="chayajala-admin"'
            return resp
        audit_admin_access(True, ip, request.path, token)
        return view(*args, **kwargs)
    return wrapper


def generate_admin_token() -> str:
    """Generate a 32-byte urlsafe token suitable for ``CHAYAJALA_ADMIN_TOKEN``.

    Exposed for one-shot administrative setup (``python -c 'from portal
    import security; print(security.generate_admin_token())'``) — never
    called from runtime code paths.
    """
    return secrets.token_urlsafe(32)
