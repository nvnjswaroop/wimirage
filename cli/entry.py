"""``main`` entrypoint + global exception hooks (Section 4 #2, #13).

Pulled out of the legacy 700-line ``main.py`` so this file stays under
50 lines and easy to reason about. The legacy ``main.py`` becomes a
shim that re-exports ``cli.entry.main`` so :data:`pyproject.toml`'s
``[project.scripts]`` entrypoint keeps working.
"""

from __future__ import annotations

import sys
import threading

from core.models import AppConfig

from cli._logging import BANNER, DISCLAIMER, configure_logging, check_root
from cli.context import AttackContext
from cli.menu import MenuHandler


logger = configure_logging()


def _global_excepthook(t, v, tb) -> None:
    """Route any unhandled exception to the logger (Section 4 #2)."""
    logger.critical("Unhandled exception", exc_info=(t, v, tb))


def _thread_excepthook(args) -> None:
    """Default :func:`threading.excepthook` — surfaces unhandled thread
    exceptions through the same rotating-file logger.
    """
    logger.critical(
        "Unhandled thread exception",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


def main() -> None:
    """Entrypoint: banner, root check, build context, run the menu forever.

    No CLI flag parsing yet (Section 1 #10) — the interactive menu is the
    only mode. Future flag-based headless invocations land in
    :func:`_parse_args` before this point.
    """
    # Catch-all for exceptions raised off the main thread (Section 4 #2).
    sys.excepthook = _global_excepthook
    threading.excepthook = _thread_excepthook

    print(BANNER)
    print(DISCLAIMER)
    check_root()

    config = AppConfig()
    ctx = AttackContext(config)

    # Security fix S-4: install SIGINT/SIGTERM handlers that flush iptables,
    # restore IP forwarding, kill the daemon processes, and reattach the
    # wireless interfaces. Without this, a Ctrl+C mid-capture leaves the host
    # forwarding + NAT'd but with no capturer attached — easy to miss when
    # the operator is focused on the screen.
    try:
        from utils.cleanup import register_cleanup_handler
        register_cleanup_handler()
    except Exception as e:
        logger.warning(
            "Failed to install signal-driven cleanup: %s: %s",
            type(e).__name__, e,
        )

    handler = MenuHandler(ctx)
    handler.run()


if __name__ == "__main__":
    main()
