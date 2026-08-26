"""CLI-side helpers: banner, disclaimer, root-check, logger setup.

Pulled out of the legacy 700-line ``main.py`` (Section 4 #13) so that
``cli.entry`` stays tiny (just an entrypoint + excepthook).
"""

from __future__ import annotations

import os
import sys
import logging
from logging.handlers import RotatingFileHandler

from core.paths import LOGS_DIR, ensure_logs_dir


# ASCII block-art banner — clean English letters drawn with
# box-drawing characters only (no Sanskrit / Devanagari glyphs).
#
# Block-art rule: '╔═╗' / '║' / '╚═╝' / '╦ ╩' / '═' draw each stroke.
# The three rows encode ``WIFI EVIL TWIN`` in compact box-art style.
BANNER = r"""
    +===============================================================+
    |                                                               |
    |    ╦ ╦╔═╗╦═╗  ╔═╗╦═╗╦  ╔╦╗╦ ╦                                    |
    |    ║║║║╣ ╠╦╝  ║ ║╠╦╝║   ║╚╦╝                                    |
    |    ╚╩╝╚═╝╩╚═  ╚═╝╩╚═╩═╝ ╩ ╩                                     |
    |                                                               |
    |               Wi-Fi Penetration-Testing Toolkit                |
    |               v2.0  ::  authorized use only                   |
    |                                                               |
    +===============================================================+
"""

DISCLAIMER = """
\033[91m[!] DISCLAIMER: This tool is for authorized penetration testing only.
[!] Unauthorized use is illegal. Only use on networks you own or have
[!] explicit written permission to test.\033[0m"""


def configure_logging(console_level: int = logging.INFO) -> logging.Logger:
    """Configure rotating file + stream handlers; return the named logger.

    Idempotent: subsequent calls re-attach the console handler but won't
    multiply the file handlers. We split this off from ``main.py`` so the
    tests can import the logger config without spinning up the full CLI.
    """
    ensure_logs_dir()
    log_file = os.path.join(LOGS_DIR, "audit.log")

    named = logging.getLogger("wimirage")
    named.setLevel(console_level)

    # Avoid duplicate file handlers on re-import during test runs.
    if not any(
        isinstance(h, RotatingFileHandler)
        and getattr(h, "baseFilename", "").endswith("audit.log")
        for h in named.handlers
    ):
        named.addHandler(
            RotatingFileHandler(
                log_file,
                maxBytes=10_000_000,
                backupCount=5,
            )
        )

    if not any(
        isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler)
        for h in named.handlers
    ):
        named.addHandler(logging.StreamHandler())

    # Propagation is *left at default (True)* so test runs that install a
    # :class:`pytest.LogCaptureHandler` via `caplog.fixture` can see the
    # records without us wiring a bespoke test bridge.
    return named


def check_root() -> None:
    """Exit with status 1 if the effective UID is non-zero (POSIX only).

    On non-POSIX (Windows / WSL without elevation) the call is a no-op so
    tests / docs builds don't break. The actual root-gating stays via
    the ``os.geteuid`` check on Linux because that's where the tool
    actually executes ``hostapd``, ``iptables`` and friends.
    """
    if not hasattr(os, "geteuid"):  # pragma: no cover - Windows
        return
    if os.geteuid() != 0:  # pragma: no cover - need root to test
        print("\033[91m[-] This tool must be run as root.\033[0m")
        sys.exit(1)
