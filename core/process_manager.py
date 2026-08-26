"""Track and supervise child subprocesses (hostapd, dnsmasq, ...).

Section 4 #1 makes the watchdog real: each registered process may pass
``restart=True`` with a ``restart_callback``; if the process exits,
the manager re-invokes the callback to re-spawn it.
"""

import logging
import subprocess
import threading
import time
from collections.abc import Callable

logger = logging.getLogger("wimirage")

__all__ = ["ProcessManager"]


class ProcessManager:
    """Thread-safe registry + watchdog for ``subprocess.Popen`` instances."""

    def __init__(self) -> None:
        self._processes: dict[str, subprocess.Popen] = {}
        # name -> callback to invoke when (re)spawning
        self._restart_callbacks: dict[str, Callable[[], subprocess.Popen]] = {}
        self._lock = threading.Lock()
        self._watchdog_thread: threading.Thread | None = None
        self._running = False

    def register(
        self,
        name: str,
        proc: subprocess.Popen,
        restart: bool = False,
        restart_callback: Callable[[], subprocess.Popen] | None = None,
    ) -> None:
        """Track ``proc`` under ``name``; optionally spawn a per-process watchdog.

        Args:
            name: Human-readable label (e.g. ``"hostapd"``).
            proc: Already-started :class:`subprocess.Popen`.
            restart: If True, register a watchdog that re-invokes
                ``restart_callback`` when the process exits.
            restart_callback: Zero-arg callable that returns a fresh
                ``subprocess.Popen`` for ``name``.
        """
        with self._lock:
            self._processes[name] = proc
            if restart and restart_callback is not None:
                self._restart_callbacks[name] = restart_callback

        if restart and restart_callback is not None:
            t = threading.Thread(target=self._watch_one, args=(name,), daemon=True)
            t.start()

    def _watch_one(self, name: str) -> None:
        """Watchdog loop for a single named process."""
        while True:
            with self._lock:
                proc = self._processes.get(name)
                callback = self._restart_callbacks.get(name)
            if proc is None or callback is None:
                return  # deregistered
            rc = proc.poll()
            if rc is None:
                time.sleep(1.0)
                continue
            logger.warning(f"Process '{name}' exited rc={rc}; attempting restart...")
            try:
                new_proc = callback()
            except Exception as e:  # pragma: no cover - depends on caller
                # Caller-supplied callback: we genuinely don't know which
                # exception types it may raise. Logging + skipping is the
                # right call here — we don't want a buggy user callback to
                # crash the watchdog thread. Reason this is wider than the
                # rest: it's a stability contract for callers.
                logger.error(f"Restart callback for '{name}' raised: {type(e).__name__}: {e}")
                return
            with self._lock:
                self._processes[name] = new_proc
            logger.info(f"Process '{name}' restarted (pid={new_proc.pid}).")

    def kill(self, name: str) -> bool:
        """Terminate the process named ``name``. Return True if one was killed."""
        with self._lock:
            proc = self._processes.pop(name, None)
            self._restart_callbacks.pop(name, None)
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            return True
        return False

    def kill_all(self) -> None:
        """Terminate every registered process and stop the global watchdog."""
        self._running = False
        with self._lock:
            names = list(self._processes.keys())

        for name in names:
            self.kill(name)

        # Best-effort sweep to clear any stragglers.
        try:
            subprocess.run(
                ["killall", "hostapd"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
            subprocess.run(
                ["killall", "dnsmasq"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
            )
        except (subprocess.SubprocessError, OSError):
            # best-effort cleanup; ``killall`` may fail when dnsmasq
            # has already exited or is not present on the system.
            pass

    def is_alive(self, name: str) -> bool:
        """Return True if ``name`` exists and has not exited."""
        with self._lock:
            proc = self._processes.get(name)
        return proc is not None and proc.poll() is None

    def get_all(self) -> dict[str, subprocess.Popen]:
        """Return a shallow snapshot of currently-registered processes."""
        with self._lock:
            return dict(self._processes)

    def start_watchdog_all(self, interval: int = 5) -> None:
        """Run a SINGLE watchdog that flags dead processes (legacy entry point).

        The per-process watchdog in :meth:`register` already handles restart;
        this method just exposes a periodic "is-alive" reporter.
        """
        self._running = True

        def watch_all():
            while self._running:
                with self._lock:
                    dead = [n for n, p in self._processes.items() if p.poll() is not None]
                for name in dead:
                    logger.warning(f"Process '{name}' is no longer running.")
                time.sleep(interval)

        t = threading.Thread(target=watch_all, daemon=True)
        t.start()
        self._watchdog_thread = t
