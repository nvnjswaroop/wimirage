"""Single source of truth for filesystem paths used across the toolkit.

Every module that needed ``os.path.dirname(os.path.dirname(__file__))`` to
discover the project root now imports from here. Centralising prevents
drift between callers (mainly called out in audit reviews B3/A4) and
removes the upward import-path pattern that suggested core↔portal coupling.

All paths are absolute strings, computed once on import from ``__file__``
locations.
"""

from __future__ import annotations

import os

# Project layout, computed from this file's location
#   <root>/core/paths.py   ← this file
#   <root>/core            → core/
#   <root>/portal          → portal/
#   <root>/config          → config/
#   <root>/logs            → logs/
#   <root>/docs            → docs/
THIS_FILE = os.path.abspath(__file__)
CORE_DIR = os.path.dirname(THIS_FILE)
PROJECT_ROOT = os.path.dirname(CORE_DIR)

PORTAL_TEMPLATES_DIR = os.path.join(PROJECT_ROOT, "portal", "templates")
PORTAL_STATIC_DIR = os.path.join(PROJECT_ROOT, "portal", "static")
CONFIG_DIR = os.path.join(PROJECT_ROOT, "config")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")


# Runtime config files; written by RogueAP at runtime
HOSTAPD_CONF_PATH = os.path.join(CONFIG_DIR, "hostapd.conf")
DNSMASQ_CONF_PATH = os.path.join(CONFIG_DIR, "dnsmasq.conf")

# PID files for the daemons (used by hostapd/dnsmasq CLI flag)
HOSTAPD_PID_PATH = "/tmp/hostapd.pid"
DNSMASQ_PID_PATH = "/tmp/dnsmasq.pid"

# Default credential log path
DEFAULT_LOG_FILE = os.path.join(LOGS_DIR, "captured_credentials.jsonl")


def ensure_logs_dir() -> None:
    """Create the logs directory if missing. Idempotent."""
    os.makedirs(LOGS_DIR, exist_ok=True)


def ensure_config_dir() -> None:
    """Create the config directory if missing. Idempotent."""
    os.makedirs(CONFIG_DIR, exist_ok=True)


__all__ = [
    "PROJECT_ROOT",
    "CORE_DIR",
    "PORTAL_TEMPLATES_DIR",
    "PORTAL_STATIC_DIR",
    "CONFIG_DIR",
    "LOGS_DIR",
    "DOCS_DIR",
    "HOSTAPD_CONF_PATH",
    "DNSMASQ_CONF_PATH",
    "HOSTAPD_PID_PATH",
    "DNSMASQ_PID_PATH",
    "DEFAULT_LOG_FILE",
    "ensure_logs_dir",
    "ensure_config_dir",
]
