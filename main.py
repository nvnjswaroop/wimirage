"""Top-level shim — :data:`pyproject.toml`'s ``[project.scripts]`` entrypoint.

The actual implementation lives in :mod:`cli.entry`; this file re-exports
``main`` so :data:`pyproject.toml`'s ``[project.scripts]`` (``wifi-eviltwin
= main:main``) keeps working.

It also re-exports the few legacy symbols the integration tests patch
via ``monkeypatch.setattr("main.<Sym>", ...)`` (Section 4 #13).
Stability of this public surface is a *deliberate* compatibility contract.

History:
    Pre-split, this file was a 700-line monolith mixing banner / root
    check / logging / state-context / 10 menu actions / excepthook. It is
    now a single import. See :mod:`cli.__init__` for the new layout.
"""

from cli.entry import main
from cli.context import AttackContext
from cli.menu import MenuHandler

# Public re-exports — the integration test suite patches these attrs on
# this module name. ``cli.menu`` resolves them at name-lookup time, not
# import-time (via ``from cli.menu import _APScanner as ...`` etc. with
# late binding), so monkeypatch.setattr here propagates to the menu
# action code. Keep this list in sync with :data:`cli.menu.REEXPORTED`.
from core.scanner import APScanner  # noqa: F401
from core.deauth import DeauthAttack  # noqa: F401
from core.rogue_ap import RogueAP  # noqa: F401
from core.network import NetworkConfig  # noqa: F401
from core.captive_portal import CaptivePortal  # noqa: F401

__all__ = [
    "main",
    "AttackContext",
    "MenuHandler",
    "APScanner",
    "DeauthAttack",
    "RogueAP",
    "NetworkConfig",
    "CaptivePortal",
]


if __name__ == "__main__":
    main()
