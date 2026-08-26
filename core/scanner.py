"""802.11 access-point scanner.

Captures beacon and data frames with Scapy, parses out SSID / channel /
encryption / signal / clients, surfaces a sorting/selector API, and
hands the result back as a structured :class:`ScanResult`.
"""

import queue
import struct
import threading
import time
import logging
from dataclasses import dataclass, field

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
from scapy.sendrecv import sniff

from core.models import AccessPoint

logger = logging.getLogger("wimirage")

__all__ = ["APScanner", "ScanResult"]


@dataclass
class ScanResult:
    """Structured result of a scan (Section 2 #7)."""
    aps: list[AccessPoint] = field(default_factory=list)
    duration: float = 0.0
    packet_count: int = 0


# BPF filter at the kernel boundary (Section 5 #7):
#   - type=mgt subtype=beacon   → AP advertisements
#   - type=data                 → client association traffic
# Re-exported as a class attribute so ``self.BPF_FILTER`` keeps working
# inside ``APScanner.scan`` for any code that captured the old shape.
BPF_FILTER = "type mgt subtype beacon or type data"


# Section 5 #6 — batch packets to amortise handler overhead.
_PACKET_QUEUE_MAXSIZE = 1000
_PACKET_BATCH_SIZE = 100


class APScanner:
    """Scan a monitor-mode interface for access points.

    Args:
        interface: Wireless interface in monitor mode.
        timeout: Scan duration in seconds.

    Attributes:
        ap_list: BSSID → :class:`AccessPoint` mapping, filled as packets arrive.

    Class Attributes:
        BPF_FILTER: Mirrors the module-level ``BPF_FILTER`` constant.
    """

    # Mirror for legacy callers and ``self.BPF_FILTER`` lookups in ``scan``.
    BPF_FILTER = BPF_FILTER

    def __init__(self, interface: str, timeout: int = 30) -> None:
        self.interface = interface
        self.timeout = timeout
        self.ap_list: dict[str, AccessPoint] = {}
        self._stop_event = threading.Event()
        self._sorted_cache: list[AccessPoint] | None = None  # Section 5 #10
        # Section 4 #L — packet-handler thread mutates ``ap_list``/``_sorted_cache``
        # while ``get_sorted_aps`` reads them. Without this lock the sorted cache
        # can return a list backed by a frozen/different object mid-update.
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Scapy handlers
    # ------------------------------------------------------------------

    def _packet_handler(self, pkt) -> None:
        """Scapy callback: enqueue the packet for batched processing."""
        q = getattr(self, "_pkt_queue", None)
        if q is None:
            return
        try:
            q.put(pkt, block=False)
        except queue.Full:
            pass  # Drop on overflow; the next batch picks up.

    def _process_batch(self, batch: list) -> None:
        """Handle a batch of packets; iterates over BEACON + DATA frames."""
        from scapy.error import Scapy_Exception
        for pkt in batch:
            try:
                if pkt.haslayer(Dot11Beacon):
                    self._handle_beacon(pkt)
                elif pkt.haslayer(Dot11) and pkt[Dot11].type == 2:
                    # 2 = data frame
                    self._handle_data(pkt)
            except (AttributeError, TypeError, KeyError, Scapy_Exception) as e:
                logger.warning(f"Packet handler error: {type(e).__name__}: {e}")

    def _beacon_worker(self, q: "queue.Queue") -> None:
        """Drain ``q`` in batches of up to ``_PACKET_BATCH_SIZE`` packets."""
        while not self._stop_event.is_set():
            batch: list = []
            try:
                first = q.get(timeout=0.5)
            except queue.Empty:
                continue
            batch.append(first)
            while len(batch) < _PACKET_BATCH_SIZE:
                try:
                    batch.append(q.get_nowait())
                except queue.Empty:
                    break
            self._process_batch(batch)

    def _handle_beacon(self, pkt) -> None:
        """Insert or update an AP entry from a beacon frame."""
        bssid = pkt[Dot11].addr2
        if bssid in self.ap_list:
            self._update_signal(pkt, bssid)
            return

        ssid = self._extract_ssid(pkt)
        channel = self._extract_channel(pkt)
        encryption = self._detect_encryption(pkt)
        signal = self._extract_signal(pkt)

        self.ap_list[bssid] = AccessPoint(
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            signal=signal,
            encryption=encryption,
            clients=[],
        )
        # Invalidate the sorted cache (Section 5 #10). Held under the
        # same lock as ``get_sorted_aps`` to avoid a torn read.
        with self._cache_lock:
            self._sorted_cache = None

    def _update_signal(self, pkt, bssid: str) -> None:
        """Replace the stored signal for ``bssid`` if the new one is stronger."""
        signal = self._extract_signal(pkt)
        if signal is not None:
            current = self.ap_list[bssid].signal
            if current is None or signal > current:
                self.ap_list[bssid].signal = signal
                with self._cache_lock:
                    self._sorted_cache = None

    def _extract_ssid(self, pkt) -> str:
        """Return the SSID of the beacon's AP (ID=0 IE), or ``<hidden>``."""
        try:
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    return elt.info.decode(errors="ignore")
                # IE list is a singly-linked chain via the .payload attribute.
                elt = elt.payload if elt.payload else None
        except (AttributeError, TypeError, struct.error):
            pass
        return "<hidden>"

    def _extract_channel(self, pkt) -> int:
        """Return the operating channel via the DS Parameter Set (ID=3 IE)."""
        try:
            dsset = pkt.getlayer(Dot11Elt, ID=3)
            if dsset and dsset.info:
                return dsset.info[0]
        except (AttributeError, TypeError, struct.error, IndexError):
            pass
        return 1

    def _extract_signal(self, pkt) -> int | None:
        """Return dBm signal strength from the RadioTap header, or None."""
        try:
            rt = pkt.getlayer(RadioTap)
            if rt and rt.dBm_AntSignal:
                raw = rt.dBm_AntSignal
                return -(256 - raw) if raw > 0 else raw
        except (AttributeError, TypeError, struct.error):
            pass
        return None

    def _detect_encryption(self, pkt) -> str:
        """Infer WPA / WPA2 / OPEN from the beacon IE chain."""
        try:
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 48:
                    return "WPA2"  # RSN IE
                if elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":
                    return "WPA"   # Vendor-specific WPA IE
                elt = elt.payload if elt.payload else None
        except (AttributeError, TypeError, struct.error, IndexError):
            pass
        return "OPEN"

    def _handle_data(self, pkt) -> None:
        """Attach the data-frame's source MAC as a client of its BSSID AP."""
        try:
            addr1 = pkt[Dot11].addr1
            addr2 = pkt[Dot11].addr2
            bssid = (
                addr2 if addr2 in self.ap_list
                else (addr1 if addr1 in self.ap_list else None)
            )
            if not bssid:
                return
            client_mac = addr1 if addr2 == bssid else addr2
            if client_mac == "ff:ff:ff:ff:ff:ff" or client_mac == bssid:
                return
            ap = self.ap_list[bssid]
            if client_mac not in ap.clients:
                ap.clients.append(client_mac)
                with self._cache_lock:
                    self._sorted_cache = None
        except (AttributeError, TypeError, KeyError) as e:
            logger.warning(
                "Scanner data-frame handler dropped packet: %s: %s",
                type(e).__name__, e,
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self) -> ScanResult:
        """Run the scan for ``self.timeout`` seconds and return a ScanResult.

        Wires up an in-process queue + batch worker so the hot Scapy path
        only does a queue.put — the heavy lifting happens off the capture
        thread (Section 5 #6).
        """
        with self._cache_lock:
            self.ap_list = {}
            self._sorted_cache = None
        self._stop_event.clear()
        self._pkt_queue = queue.Queue(maxsize=_PACKET_QUEUE_MAXSIZE)

        logger.info(
            f"Scanning for access points on {self.interface} for {self.timeout} seconds..."
        )

        # Batched worker thread.
        worker = threading.Thread(
            target=self._beacon_worker, args=(self._pkt_queue,), daemon=True
        )
        worker.start()

        start = time.monotonic()
        sniff_thread = threading.Thread(
            target=sniff,
            kwargs={
                "iface": self.interface,
                "prn": self._packet_handler,
                "timeout": self.timeout,
                "stop_filter": lambda p: self._stop_event.is_set(),
                "filter": self.BPF_FILTER,
            },
            daemon=True,
        )
        sniff_thread.start()

        # Wait for sniff to wind down (timeout + buffer).
        sniff_thread.join(timeout=self.timeout + 2)
        # Stop the worker once sniff is done (Section 4 #8 — no fragile timeout).
        self._stop_event.set()
        worker.join(timeout=2)

        duration = time.monotonic() - start
        result = ScanResult(
            aps=self.get_sorted_aps(),
            duration=duration,
            packet_count=len(self.ap_list),
        )
        return result

    def stop(self) -> None:
        """Signal the worker to stop early."""
        self._stop_event.set()

    def get_sorted_aps(self) -> list[AccessPoint]:
        """Return APs sorted by descending signal strength (cached)."""
        with self._cache_lock:
            if self._sorted_cache is None:
                self._sorted_cache = sorted(
                    self.ap_list.values(),
                    key=lambda x: x.signal if x.signal is not None else -100,
                    reverse=True,
                )
            return list(self._sorted_cache)

    def display_aps(self, aps: list[AccessPoint] | None = None) -> list[AccessPoint]:
        """Pretty-print the access-point table; return the list unchanged."""
        if aps is None:
            aps = self.get_sorted_aps()

        print("\n" + "=" * 100)
        print(f"{'#':<5} {'SSID':<25} {'BSSID':<20} {'CH':<5} {'Signal':<10} {'Encryption':<12} {'Clients'}")
        print("=" * 100)

        for idx, ap in enumerate(aps, 1):
            ssid_display = ap.ssid[:24] if ap.ssid else "<hidden>"
            signal_display = f"{ap.signal} dBm" if ap.signal is not None else "N/A"
            client_count = len(ap.clients)
            print(
                f"{idx:<5} {ssid_display:<25} {ap.bssid:<20} {ap.channel:<5} "
                f"{signal_display:<10} {ap.encryption:<12} {client_count}"
            )

        print("=" * 100 + "\n")
        return aps

    def select_ap(self, aps: list[AccessPoint], index: int) -> AccessPoint | None:
        """Pick the ``index``-th AP (1-indexed) from ``aps``."""
        if 0 < index <= len(aps):
            selected = aps[index - 1]
            print(f"\n[+] Selected AP: {selected.ssid} ({selected.bssid}) CH:{selected.channel}")
            return selected
        print("[-] Invalid selection.")
        return None

    def get_clients(self, bssid: str) -> list[str]:
        """Return the client-MAC list for ``bssid`` (empty if unknown)."""
        if bssid in self.ap_list:
            return self.ap_list[bssid].clients
        return []
