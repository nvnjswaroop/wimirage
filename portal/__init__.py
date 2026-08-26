"""portal package — Flask template / static assets + route blueprints."""

# Note: imports are intentionally NOT done at package init. ``portal.routes``
# and ``portal.admin`` both reach back through ``core.captive_portal`` for
# their dependency injection.  Importing them eagerly here creates a
# circular-import cycle.  Callers should import the builders from their
# canonical locations: ``from portal.routes import build_portal_blueprint``,
# ``from portal.admin import build_admin_blueprint``.

__all__ = ["build_portal_blueprint", "build_admin_blueprint"]
