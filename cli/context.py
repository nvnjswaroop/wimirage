"""Shared mutable state passed between CLI menu actions.

Pulled out of the legacy 700-line ``main.py`` (Section 4 #13). Owns the
:class:`AttackState` machine, every long-running subsystem (scanner /
deauth / rogue AP / network / portal), and the cross-cutting
:class:`EventBus` / :class:`ProcessManager` / :class:`CredentialLogger`.

Keep this file cheap: it should never *do* anything except keep state.
UI work belongs in :mod:`cli.menu`; orchestration belongs in
:mod:`cli.entry`.
"""

from __future__ import annotations

import logging
from typing import Optional

from core.events import EventBus
from core.models import AccessPoint, AppConfig, AttackState
from core.network import NetworkConfig
from core.captive_portal import CaptivePortal
from core.process_manager import ProcessManager
from core.scanner import APScanner
from core.deauth import DeauthAttack
from core.rogue_ap import RogueAP
from utils.cleanup import Cleanup
from utils.logger import CredentialLogger


logger = logging.getLogger("wimirage")


class AttackContext:
    """Shared mutable state passed between menu actions.

    Args:
        config: Application-wide configuration.
        logger_instance: Optional pre-built :class:`CredentialLogger`. When
            ``None``, a fresh one is constructed so callers who don't care
            don't have to wire one in (Dependency Injection).
    """

    def __init__(
        self,
        config: AppConfig,
        logger_instance: Optional[CredentialLogger] = None,
    ) -> None:
        self.config = config
        self.state = AttackState.IDLE
        self.target_ap: Optional[AccessPoint] = None
        self.scanner: Optional[APScanner] = None
        self.deauth: Optional[DeauthAttack] = None
        self.rogue_ap: Optional[RogueAP] = None
        self.network: Optional[NetworkConfig] = None
        self.portal: Optional[CaptivePortal] = None
        self.mon_interface: Optional[str] = None
        self.ap_interface: Optional[str] = None
        self.internet_interface: Optional[str] = None
        self.cleaner: Optional[Cleanup] = None
        self.event_bus = EventBus()
        self.process_manager = ProcessManager()
        self.cred_logger: CredentialLogger = logger_instance or CredentialLogger()

    def can_transition(self, new_state: AttackState) -> bool:
        """Return True if ``self.state -> new_state`` is permitted.

        Allows ``FULL_ATTACK -> PORTAL_RUNNING`` and
        ``PORTAL_RUNNING -> IDLE`` (run only the portal subset of the chain).
        """
        valid_transitions = {
            AttackState.IDLE: [AttackState.SCANNING],
            AttackState.SCANNING: [AttackState.SCANNED, AttackState.IDLE],
            AttackState.SCANNED: [AttackState.TARGET_SELECTED, AttackState.SCANNING],
            AttackState.TARGET_SELECTED: [
                AttackState.DEAUTH_RUNNING,
                AttackState.SCANNING,
            ],
            AttackState.DEAUTH_RUNNING: [
                AttackState.AP_RUNNING,
                AttackState.TARGET_SELECTED,
            ],
            AttackState.AP_RUNNING: [
                AttackState.PORTAL_RUNNING,
                AttackState.DEAUTH_RUNNING,
                AttackState.FULL_ATTACK,
            ],
            AttackState.PORTAL_RUNNING: [AttackState.IDLE],
            AttackState.FULL_ATTACK: [AttackState.IDLE, AttackState.PORTAL_RUNNING],
        }
        allowed = valid_transitions.get(self.state, [])
        return new_state in allowed or new_state == AttackState.IDLE

    def transition(self, new_state: AttackState) -> bool:
        """Move ``self.state`` to ``new_state`` if allowed; log the result.

        Returns:
            True if the transition was applied, False otherwise.
        """
        if self.can_transition(new_state):
            logger.info(
                f"State transition: {self.state.name} -> {new_state.name}"
            )
            self.state = new_state
            return True
        logger.warning(
            f"Invalid state transition: {self.state.name} -> {new_state.name}"
        )
        print(
            f"[-] Cannot go from {self.state.name} to {new_state.name}. "
            "Follow the proper order."
        )
        return False


__all__ = ["AttackContext"]
