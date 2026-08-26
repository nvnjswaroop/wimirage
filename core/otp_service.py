"""OTP generation, verification & delivery.

Public surface:
    - :class:`OTPServiceInterface` — abstract contract
    - :class:`BaseOTPService` — in-memory store with SHA-256 + ``hmac.compare_digest``
    - :class:`DemoOTPService` — prints OTPs to stdout (no SMS)
    - :class:`TwilioOTPService` — uses the ``twilio`` package
    - :data:`VALID_COUNTRY_CODES` — server-side allowlist
    - :class:`OTPBackendError` — wrapper raised by any concrete backend
      on transient delivery failures so callers can ``except
      OTPBackendError`` without coupling to vendor SDKs like Twilio.

Extension example::

    class MySmsService(BaseOTPService):
        def send_otp(self, phone, otp):
            ...  # call your SMS gateway here

Extending doesn't require subclassing ``OTPServiceInterface`` if you only
want to override delivery. ``CaptivePortal`` accepts any concrete
``OTPServiceInterface`` instance.
"""

import base64
import hashlib
import hmac
import logging
import random
import secrets as _secrets
import time
from abc import ABC, abstractmethod


class OTPBackendError(RuntimeError):
    """Raised by OTP backends when delivery fails.

    Wraps any backend-specific exception (Twilio TwilioRestException,
    network OSError, etc.) so that route handlers can catch a stable
    contract instead of hard-coding vendor SDK exception types.
    """

# Twilio is an optional dependency. Import lazily so the rest of the module
# remains usable when twilio isn't installed (Section 8 #10).
try:
    from twilio.rest import Client as _TwilioClient
    _TWILIO_IMPORT_ERROR: Exception | None = None
except Exception as _exc:  # pragma: no cover - exercised when twilio missing
    _TwilioClient = None
    _TWILIO_IMPORT_ERROR = _exc

logger = logging.getLogger("wimirage")

__all__ = [
    "OTPServiceInterface",
    "BaseOTPService",
    "DemoOTPService",
    "TwilioOTPService",
    "OTPBackendError",
    "VALID_COUNTRY_CODES",
]


class OTPServiceInterface(ABC):
    """Abstract base for OTP delivery + verification."""

    @abstractmethod
    def send_otp(self, phone: str, otp: str) -> None:
        """Deliver ``otp`` to ``phone`` (SMS, demo print, ...)."""

    @abstractmethod
    def verify_otp(self, phone: str, otp_input: str) -> bool:
        """Return True if ``otp_input`` matches the active OTP for ``phone``."""

    @abstractmethod
    def generate_otp(self, phone: str) -> str:
        """Generate a fresh OTP for ``phone`` and store its hash; return plaintext."""


class BaseOTPService(OTPServiceInterface):
    """In-memory OTP store with hash + timing-safe comparison.

    Args:
        otp_length: Number of digits per OTP.
        expiry_seconds: How long an OTP stays valid.
        max_attempts: Wrong guesses before lockout.
        lockout_seconds: Lockout duration after too many failures.
    """

    DEFAULT_LENGTH = 6
    DEFAULT_EXPIRY = 300
    DEFAULT_MAX_ATTEMPTS = 5
    DEFAULT_LOCKOUT = 600

    def __init__(
        self,
        otp_length: int = DEFAULT_LENGTH,
        expiry_seconds: int = DEFAULT_EXPIRY,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        lockout_seconds: int = DEFAULT_LOCKOUT,
    ) -> None:
        self.otp_length = otp_length
        self.expiry_seconds = expiry_seconds
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._otp_store: dict[str, dict] = {}
        self._attempt_counts: dict[str, dict] = {}

    @staticmethod
    def _hash_otp(otp: str, salt: bytes) -> str:
        """SHA-256 over ``salt || otp`` returned as hex.

        Per-OTP salt defeats precomputed rainbow tables on stored hashes:
        a SHA-256 of all 10^6 six-digit OTPs is one dictionary build away
        from cracking the entire unsalted store.
        """
        digest = hashlib.sha256(salt + otp.encode()).hexdigest()
        return f"{base64.b64encode(salt).decode()}${digest}"

    def generate_otp(self, phone: str) -> str:
        """Mint a new OTP for ``phone``; return the plaintext.

        Stores ``salt_b64$sha256(salt||otp)`` rather than a raw SHA-256
        digest so an attacker who exfiltrates the in-memory store still
        has to brute-force a per-entry 16-byte salt in addition to the
        6-digit OTP.
        """
        otp = "".join(str(random.randint(0, 9)) for _ in range(self.otp_length))
        salt = _secrets.token_bytes(16)
        self._otp_store[phone] = {
            "otp_hash": self._hash_otp(otp, salt),
            "otp_version": 2,  # 2 = salted; 1 = legacy unsalted.
            "created_at": time.time(),
        }
        self._attempt_counts[phone] = {"count": 0, "locked_at": None}
        return otp

    def verify_otp(self, phone: str, otp_input: str) -> bool:
        """Return True iff ``otp_input`` matches the active OTP for ``phone``.

        Constant-time comparison via :func:`hmac.compare_digest` against
        ``sha256(salt||otp_input)``. Legacy unsalted entries (no ``$``
        delimiter) still verify so an in-flight store from an older
        visitor isn't invalidated by an upgrade; a single
        ``logger.warning`` flags them so the operator can wipe old state.
        """
        if phone not in self._otp_store:
            return False

        attempts = self._attempt_counts.get(phone, {"count": 0, "locked_at": None})

        if attempts.get("locked_at") and time.time() - attempts["locked_at"] < self.lockout_seconds:
            remaining = int(self.lockout_seconds - (time.time() - attempts["locked_at"]))
            logger.warning(f"Account locked for {remaining}s. Too many failed attempts.")
            return False

        if attempts.get("locked_at") and time.time() - attempts["locked_at"] >= self.lockout_seconds:
            self._attempt_counts[phone] = {"count": 0, "locked_at": None}

        stored = self._otp_store[phone]

        if time.time() - stored["created_at"] > self.expiry_seconds:
            del self._otp_store[phone]
            logger.warning("OTP has expired.")
            return False

        stored_hash = stored["otp_hash"]

        if "$" in stored_hash:
            salt_b64, _, digest = stored_hash.partition("$")
            try:
                salt = base64.b64decode(salt_b64, validate=False)
            except (ValueError, TypeError):
                logger.warning("Corrupt OTP salt detected; rejecting.")
                return False
            input_hash = hashlib.sha256(salt + otp_input.encode()).hexdigest()
            constructed = f"{salt_b64}${input_hash}"
        else:
            # Legacy unsalted path — pre-2.0 verifier. Logged for awareness.
            logger.warning(
                "Verifying legacy unsalted OTP entry for %s; "
                "regenerate OTPs to migrate.", phone
            )
            input_hash = hashlib.sha256(otp_input.encode()).hexdigest()
            constructed = input_hash

        if hmac.compare_digest(constructed, stored_hash):
            del self._otp_store[phone]
            if phone in self._attempt_counts:
                del self._attempt_counts[phone]
            return True

        # Wrong guess — track attempts.
        self._attempt_counts.setdefault(phone, {"count": 0, "locked_at": None})
        self._attempt_counts[phone]["count"] += 1
        attempts_left = self.max_attempts - self._attempt_counts[phone]["count"]

        if attempts_left <= 0:
            self._attempt_counts[phone]["locked_at"] = time.time()
            del self._otp_store[phone]
            logger.warning(f"Too many failed attempts. Locked for {self.lockout_seconds}s.")
            return False

        logger.warning(f"Invalid OTP. {attempts_left} attempts remaining.")
        return False

    def is_locked(self, phone: str) -> bool:
        """Return True if ``phone`` is currently rate-limited from extra attempts."""
        attempts = self._attempt_counts.get(phone)
        if not attempts or not attempts.get("locked_at"):
            return False
        return time.time() - attempts["locked_at"] < self.lockout_seconds

    def send_otp(self, phone: str, otp: str) -> None:
        """Stub delivery — :class:`BaseOTPService` itself doesn't ship messages.

        Subclasses (``DemoOTPService``, ``TwilioOTPService``) override this
        with real backends. Calling this stub raises ``NotImplementedError``
        rather than silently no-oping, so the failure is loud at the
        ``generate_otp`` → ``send_otp`` boundary instead of eaten.
        """
        raise NotImplementedError(
            "BaseOTPService does not implement send_otp; "
            "use DemoOTPService or TwilioOTPService for delivery."
        )


class DemoOTPService(BaseOTPService):
    """Prints OTP values to the log — for offline demos only."""

    def send_otp(self, phone: str, otp: str) -> None:
        logger.info(f"DEMO MODE: OTP {otp} would be sent to {phone}")

    def generate_otp(self, phone: str) -> str:
        otp = super().generate_otp(phone)
        logger.info(f"DEMO OTP for {phone}: {otp}")
        return otp


class TwilioOTPService(BaseOTPService):
    """Sends OTPs via Twilio's REST API.

    Args:
        account_sid: Twilio Account SID.
        auth_token: Twilio Auth Token.
        from_phone: Twilio-provisioned sender phone number (E.164).
        otp_length: See :class:`BaseOTPService`.
        expiry_seconds: See :class:`BaseOTPService`.
        max_attempts: See :class:`BaseOTPService`.
        lockout_seconds: See :class:`BaseOTPService`.
    """

    def __init__(self, account_sid: str, auth_token: str, from_phone: str,
                 otp_length: int = BaseOTPService.DEFAULT_LENGTH,
                 expiry_seconds: int = BaseOTPService.DEFAULT_EXPIRY,
                 max_attempts: int = BaseOTPService.DEFAULT_MAX_ATTEMPTS,
                 lockout_seconds: int = BaseOTPService.DEFAULT_LOCKOUT) -> None:
        super().__init__(otp_length, expiry_seconds, max_attempts, lockout_seconds)
        self.account_sid = account_sid
        self.auth_token = auth_token
        self.from_phone = from_phone
        # Build the client once at construction time (Section 5 #8).
        if _TwilioClient is None:
            raise RuntimeError(
                "Twilio package not installed. Run: pip install twilio"
            ) from _TWILIO_IMPORT_ERROR
        self._client = _TwilioClient(account_sid, auth_token)

    def send_otp(self, phone: str, otp: str) -> None:
        """POST the OTP to Twilio; raise :class:`OTPBackendError` on failure.

        Twilio's SDK raises vendor-specific exception types. We catch
        the broad family (``requests`` + Twilio + generic OSError) and
        re-raise as :class:`OTPBackendError` so callers don't have to
        import the Twilio SDK to handle transient errors.
        """
        try:
            message = self._client.messages.create(
                body=f"Your Wi-Fi verification code is: {otp}. Valid for 5 minutes.",
                from_=self.from_phone,
                to=phone,
            )
            logger.info(f"Twilio SMS sent: {message.sid}")
        except (OSError, ConnectionError, TimeoutError) as e:
            logger.error(f"Twilio transport error: {type(e).__name__}: {e}")
            raise OTPBackendError(f"SMS transport failure: {e}") from e
        except Exception as e:  # twilio.rest.TwilioException and friends
            # Reason: Twilio raises vendor-specific exception types not
            # part of the standard library (TwilioRestException + many).
            # We re-raise as OTPBackendError so callers need not import
            # the Twilio SDK to handle delivery failures gracefully.
            logger.error(f"Twilio error: {type(e).__name__}: {e}")
            raise OTPBackendError(f"SMS delivery failed: {e}") from e


VALID_COUNTRY_CODES = [
    "+91", "+1", "+44", "+61", "+81", "+49", "+33", "+86", "+971", "+65",
    "+92", "+880", "+94", "+977", "+974", "+968", "+966", "+20", "+27", "+234",
]
