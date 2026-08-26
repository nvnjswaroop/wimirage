"""Toggle a wireless interface between managed and monitor modes.

This wraps ``iwconfig`` / ``airmon-ng`` so the rest of the codebase can talk
to a constant API. All subprocess failures are caught and logged.
"""

import logging
import os
import re
import subprocess

logger = logging.getLogger("wimirage")

__all__ = ["MonitorMode"]


class MonitorMode:
    """Stateless helpers around ``iwconfig`` and ``airmon-ng``."""

    @staticmethod
    def get_wireless_interfaces() -> list[str]:
        """Return the names of every wireless interface visible on the host.

        Tries ``iwconfig`` first; falls back to a heuristic over ``ip link``
        output (``wl*``/``wlan*`` names) if ``iwconfig`` is missing.
        """
        interfaces: list[str] = []
        try:
            result = subprocess.run(
                ["iwconfig"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in result.stdout.split("\n"):
                # Leading whitespace is normal — `iwconfig` emits indent-before-name.
                match = re.match(r"^\s*(\S+)\s+.*IEEE 802\.11", line)
                if match:
                    interfaces.append(match.group(1))
            return interfaces
        except FileNotFoundError:
            return MonitorMode._list_interfaces_via_ip()
        except subprocess.TimeoutExpired:
            logger.error("iwconfig timed out.")
            return interfaces
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as e:
            logger.error(f"Error getting wireless interfaces: {type(e).__name__}: {e}")
            return interfaces

    @staticmethod
    def _list_interfaces_via_ip() -> list[str]:
        """Fallback interface discovery using ``ip link`` + name heuristics."""
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            interfaces = []
            for line in result.stdout.split("\n"):
                match = re.match(r"^\d+: (\S+):", line)
                if match:
                    name = match.group(1)
                    if name.startswith("wl") or name.startswith("wlan"):
                        interfaces.append(name)
            return interfaces
        except FileNotFoundError:
            logger.error("Neither iwconfig nor ip found.")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Timeout listing interfaces via ip.")
            return []
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as e:
            logger.error(f"Error listing interfaces: {type(e).__name__}: {e}")
            return []

    @staticmethod
    def is_monitor_mode(interface: str) -> bool:
        """Return True if ``interface`` reports ``Mode:Monitor`` from ``iwconfig``."""
        try:
            result = subprocess.run(
                ["iwconfig", interface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "Mode:Monitor" in result.stdout
        except FileNotFoundError:
            return False
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout checking mode for {interface}")
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def interface_exists(interface: str) -> bool:
        """Return True if the sysfs entry for ``interface`` exists."""
        return os.path.exists(f"/sys/class/net/{interface}")

    @staticmethod
    def enable_monitor(interface: str) -> str | None:
        """Put ``interface`` into monitor mode.

        Strategy:
            1. ``airmon-ng check kill`` to free the iface
            2. ``iwconfig <iface> mode monitor``
            3. fall back to ``airmon-ng start`` if iwconfig didn't work

        Returns:
            The monitor-mode interface name (may differ from input if
            airmon-ng created a ``wlan0mon``-style name); None on failure.
        """
        if not MonitorMode.interface_exists(interface):
            logger.error(f"Interface {interface} does not exist.")
            return None

        logger.info(f"Enabling monitor mode on {interface}...")

        # airmon-ng may not be installed; ignore FileNotFoundError.
        try:
            subprocess.run(
                ["airmon-ng", "check", "kill"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        except (OSError, subprocess.SubprocessError):
            pass

        try:
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            subprocess.run(
                ["iwconfig", interface, "mode", "monitor"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except FileNotFoundError as e:
            logger.error(f"Required tool not found: {e}")
            return None
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout setting monitor mode on {interface}, trying airmon-ng...")
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as e:
            logger.warning(f"Failed to set monitor mode via iwconfig: {e}, trying airmon-ng...")

        if MonitorMode.is_monitor_mode(interface):
            logger.info(f"Monitor mode enabled on {interface}")
            return interface

        # Fall back to airmon-ng.
        try:
            subprocess.run(
                ["airmon-ng", "start", interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
            )
            mon_interfaces = MonitorMode.get_wireless_interfaces()
            for iface in mon_interfaces:
                if "mon" in iface and MonitorMode.is_monitor_mode(iface):
                    logger.info(f"Monitor interface created: {iface}")
                    return iface
        except FileNotFoundError:
            logger.error("airmon-ng not found. Install aircrack-ng.")
        except subprocess.TimeoutExpired:
            logger.error("airmon-ng timed out.")
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as e:
            logger.error(f"airmon-ng error: {e}")

        logger.error(f"Failed to enable monitor mode on {interface}")
        return None

    @staticmethod
    def disable_monitor(interface: str) -> bool:
        """Return ``interface`` to managed mode.

        Tries ``iwconfig <iface> mode managed`` first; falls back to
        ``airmon-ng stop`` if it timed out or failed.

        Returns:
            True if the interface is no longer in monitor mode.
        """
        logger.info(f"Disabling monitor mode on {interface}...")

        def _airmon_stop() -> bool:
            try:
                subprocess.run(
                    ["airmon-ng", "stop", interface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
                return True
            except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as e:
                logger.error(f"Failed to disable monitor mode via airmon-ng: {e}")
                return False

        try:
            subprocess.run(
                ["ip", "link", "set", interface, "down"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            subprocess.run(
                ["iwconfig", interface, "mode", "managed"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            subprocess.run(
                ["ip", "link", "set", interface, "up"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
        except FileNotFoundError as e:
            logger.error(f"Required tool not found: {e}")
            return False
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout disabling monitor on {interface}, trying airmon-ng...")
            if not _airmon_stop():
                return False
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as e:
            logger.error(f"Error disabling monitor mode: {e}")
            if not _airmon_stop():
                return False

        if not MonitorMode.is_monitor_mode(interface):
            logger.info(f"Monitor mode disabled on {interface}")
            return True
        logger.error(f"Failed to disable monitor mode on {interface}")
        return False

    @staticmethod
    def set_channel(interface: str, channel: int) -> bool:
        """Set the wireless channel of ``interface`` via ``iwconfig``."""
        if not MonitorMode.interface_exists(interface):
            return False
        try:
            subprocess.run(
                ["iwconfig", interface, "channel", str(channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        except (OSError, subprocess.SubprocessError):
            return False
