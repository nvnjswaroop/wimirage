"""Wi-Fi Penetration-Testing Toolkit — CLI package.

Modules:
    ``entry``     : ``main()`` entrypoint + global excepthook
    ``_logging``  : banner, disclaimer, root-check, logger setup
    ``context``   : :class:`AttackContext` (shared mutable state)
    ``menu``      : :class:`MenuHandler` (interactive session driver)

The package is imported as ``import cli.entry; cli.entry.main()``; the
top-level ``main.py`` keeps the legacy ``main:main`` entrypoint by re-
exporting ``cli.entry.main``. This split (Section 4 #13) keeps the
entrypoint hot path tiny so the menu code can evolve in a 500-line
module instead of fighting a 700-line monolith.
"""
