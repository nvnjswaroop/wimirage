from unittest.mock import MagicMock, patch

import pytest


class TestDeauthAttack:
    def test_init_defaults(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            assert attack.interface == "wlan0"
            assert attack.target_bssid == "AA:BB:CC:DD:EE:FF"
            assert attack.target_channel == 6
            assert attack.client_mac == "FF:FF:FF:FF:FF:FF"
            assert attack.pps == 100
            assert attack._running is False
            assert attack.packets_sent == 0

    def test_init_custom_pps(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6, pps=200)
            assert attack.pps == 200

    def test_init_custom_client_mac(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6, client_mac="11:22:33:44:55:66")
            assert attack.client_mac == "11:22:33:44:55:66"

    def test_build_packets_creates_packet(self):
        with (
            patch("core.deauth.Dot11") as mock_dot11,
            patch("core.deauth.Dot11Deauth") as mock_deauth,
            patch("core.deauth.RadioTap") as mock_radiotap,
        ):
            mock_dot11.return_value = MagicMock()
            mock_deauth.return_value = MagicMock()
            mock_radiotap.return_value = MagicMock()

            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            attack._build_packets()

            assert attack._packet is not None
            assert attack._reverse_packet is not None

    def test_build_packets_no_reverse_for_targeted(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6, client_mac="11:22:33:44:55:66")
            attack._build_packets()
            assert attack._reverse_packet is None

    @patch("subprocess.run")
    def test_set_channel(self, mock_run):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            attack.set_channel()
            mock_run.assert_called()

    def test_set_pps_valid(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            attack.set_pps(500)
            assert attack.pps == 500

    def test_set_pps_invalid_zero(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            with pytest.raises(ValueError):
                attack.set_pps(0)

    def test_set_pps_invalid_negative(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            with pytest.raises(ValueError):
                attack.set_pps(-10)

    def test_set_target(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            attack.set_target("11:22:33:44:55:66", 11)
            assert attack.target_bssid == "11:22:33:44:55:66"
            assert attack.target_channel == 11

    def test_is_running_default(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            assert attack.is_running() is False

    def test_stop_when_not_running(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            attack = DeauthAttack("wlan0", "AA:BB:CC:DD:EE:FF", 6)
            attack.stop()
            assert attack._running is False

    def test_broadcast_mac_constant(self):
        with (
            patch("core.deauth.Dot11"),
            patch("core.deauth.Dot11Deauth"),
            patch("core.deauth.RadioTap"),
        ):
            from core.deauth import DeauthAttack

            assert DeauthAttack.BROADCAST_MAC == "FF:FF:FF:FF:FF:FF"
