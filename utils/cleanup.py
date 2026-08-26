"""Restore host state after a run: flush iptables, kill daemons, re-attach.

Exposes :class:`Cleanup` and :func:`register_cleanup_handler` which installs
SIGINT/SIGTERM handlers that tear everything down on Ctrl+C.
"""

import logging
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from functools import wraps
from typing import TypeVar

from core.network import flush_iptables, restore_iptables

logger = logging.getLogger("wimirage")

__all__ = ["Cleanup", "register_cleanup_handler", "retry", "request_shutdown"]


F = TypeVar("F", bound=Callable[..., object])

# Module-level cooperative-shutdown signal. ``do_full_chain`` blocks on
# this Event during long-running capture, so SIGINT/SIGTERM from the
# operator actually breaks the wait instead of leaving the loop to time
# out on the 1.0s tick. Use request_shutdown() to set it from anywhere;
# importers reading is_shutdown_requested() can decide whether to also
# sys.exit().
_shutdown_event = threading.Event()
shutdown_event = _shutdown_event  # canonical alias for cross-module import


def request_shutdown() -> None:
    """Signal any thread blocked on ``is_shutdown_requested`` to wake up.

    Safe to call from a signal handler and from anywhere else; idempotent.
    """
    _shutdown_event.set()


def is_shutdown_requested() -> bool:
    """Return True if :func:`request_shutdown` has been called."""
    return _shutdown_event.is_set()


def reset_shutdown() -> None:
    """Clear the shutdown flag (used by tests that re-drive the same flow)."""
    _shutdown_event.clear()


def retry(max_attempts: int = 3, delay: float = 1.0, exceptions: tuple = (Exception,)):
    """Decorator: re-invoke ``fn`` up to ``max_attempts`` on transient errors.

    Used on subprocess-bound calls (Section 4 #3).
    """

    def decorator(fn: F) -> F:
        @wraps(fn)
        def wrapped(*args, **kwargs):
            last: BaseException | None = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as e:
                    last = e
                    logger.warning(f"{fn.__name__} attempt {attempt}/{max_attempts} failed: {e}")
                    if attempt < max_attempts:
                        time.sleep(delay)
            assert last is not None
            raise last

        return wrapped  # type: ignore[return-value]

    return decorator


class Cleanup:
    """Best-effort restoration of network/interface state.

    Args:
        interfaces: Wireless interfaces that were used during the run
            (will be restored from monitor → managed).
        internet_interface: WAN-side interface (unused at the moment).
    """

    RETRY_ATTEMPTS = 3
    RETRY_DELAY = 2

    def __init__(
        self,
        interfaces: list[str] | None = None,
        internet_interface: str | None = None,
    ) -> None:
        self.interfaces = interfaces or []
        self.internet_interface = internet_interface
        self._processes: list[subprocess.Popen] = []

    def register_process(self, proc: subprocess.Popen) -> None:
        """Track ``proc`` for cleanup at teardown."""
        self._processes.append(proc)

    @retry(
        max_attempts=RETRY_ATTEMPTS,
        delay=RETRY_DELAY,
        exceptions=(subprocess.TimeoutExpired, Exception),
    )
    def restore_interfaces(self) -> None:
        """Disable monitor mode + flush IP + rerun dhclient for every iface."""
        from utils.monitor_mode import MonitorMode

        for iface in self.interfaces:
            logger.info(f"Restoring interface {iface}...")
            try:
                MonitorMode.disable_monitor(iface)
                subprocess.run(
                    ["ip", "addr", "flush", "dev", iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                subprocess.run(
                    ["dhclient", "-r", iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
                subprocess.run(
                    ["dhclient", iface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            except subprocess.TimeoutExpired as e:
                logger.warning(f"Timeout restoring interface {iface}: {e}")
                raise
            except FileNotFoundError as e:
                logger.error(f"dhclient/iwconfig not found for {iface}: {e}")
                return
            except (subprocess.SubprocessError, OSError) as e:
                logger.error(f"Error restoring {iface}: {type(e).__name__}: {e}")
                raise

    def disable_ip_forwarding(self) -> None:
        """Best-effort: write 0 to ``/proc/sys/net/ipv4/ip_forward``."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            logger.info("IP forwarding disabled.")
        except (PermissionError, OSError) as e:
            logger.error(f"Failed to disable IP forwarding: {type(e).__name__}: {e}")

    def kill_background_processes(self) -> None:
        """``killall hostapd`` + ``killall dnsmasq`` + terminate tracked procs."""
        for proc_name in ["hostapd", "dnsmasq"]:
            for _attempt in range(self.RETRY_ATTEMPTS):
                try:
                    result = subprocess.run(
                        ["killall", proc_name],
                        capture_output=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        break
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout killing {proc_name}")
                except FileNotFoundError:
                    return
                except (subprocess.SubprocessError, OSError) as e:
                    logger.error(f"Error killing {proc_name}: {type(e).__name__}: {e}")
                    return

        for proc in self._processes:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            except (OSError, subprocess.SubprocessError):
                # Best-effort kill: don't let one stubborn process
                # block the rest of cleanup.
                pass

    def restart_network_manager(self) -> None:
        """Best-effort NetworkManager restart (systemd + SysV)."""
        for cmd in (
            ["systemctl", "start", "NetworkManager"],
            ["service", "network-manager", "restart"],
        ):
            try:
                subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            except (OSError, subprocess.SubprocessError) as e:
                logger.warning(
                    f"Network-manager restart via {cmd[0]} failed: {type(e).__name__}: {e}"
                )

    def cleanup_all(self) -> None:
        """Kills daemons, flushes iptables, disables forwarding, restores ifaces.

        Section 9 hardening: also calls :func:`restore_iptables` so the
        host's pre-attack NAT/filter snapshot (written by
        ``backup_iptables`` during ``setup_iptables``) is replayed. This
        means docker / wireguard / custom MASQUERADE chains the operator
        had before the run come back too.
        """
        logger.info("Running cleanup...")

        self.kill_background_processes()
        flush_iptables()
        # Best-effort rollback. flush above already cleared our own chains
        # so the worst case here is "log a warning, ship", not "leave
        # half-flushed state".
        restore_iptables()
        self.disable_ip_forwarding()
        try:
            self.restore_interfaces()
        except (OSError, subprocess.SubprocessError) as e:
            logger.error(f"Interface restore failed after retries: {type(e).__name__}: {e}")
        self.restart_network_manager()

        logger.info("Cleanup complete. System restored.")


_registered_cleanup: Cleanup | None = None


def register_cleanup_handler(
    interfaces: list[str] | None = None,
    internet_interface: str | None = None,
) -> Cleanup:
    """Install SIGINT/SIGTERM handlers that run ``cleanup_all`` and exit.

    Returns:
        The :class:`Cleanup` instance registered globally.
    """
    global _registered_cleanup
    cleaner = Cleanup(interfaces=interfaces, internet_interface=internet_interface)

    def handler(signum, frame):
        # Wake up any cooperative-shutdown wait (do_full_chain blocks on
        # this Event for the lifetime of an active attack). Then run the
        # cleanup_unwind. ``sys.exit`` is invoked last so cleanup runs in
        # the signal handler's context — equivalent to what the operator
        # got pre-fix, but now also breaks the wait loop instead of
        # leaving it to time out on its 1.0s tick.
        request_shutdown()
        cleaner.cleanup_all()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    _registered_cleanup = cleaner
    return cleaner
