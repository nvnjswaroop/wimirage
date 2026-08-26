from unittest.mock import patch, MagicMock
from core.models import AccessPoint
from core.scanner import BPF_FILTER, ScanResult


class TestAPScanner:
    def test_init_defaults(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0", timeout=20)
            assert scanner.interface == "wlan0"
            assert scanner.timeout == 20
            assert scanner.ap_list == {}
            assert scanner._stop_event is not None

    def test_bpf_filter_set(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            # BPF_FILTER is a module-level constant (Section 5 #7).
            assert BPF_FILTER is not None
            assert "beacon" in BPF_FILTER or "mgt" in BPF_FILTER
            # confirm orchestration invariants
            assert scanner.ap_list == {}
            assert isinstance(ScanResult(), ScanResult)

    def test_get_sorted_aps_empty(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            assert scanner.get_sorted_aps() == []

    def test_get_sorted_aps_by_signal(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            ap1 = AccessPoint(ssid="A", bssid="AA:BB:CC:DD:EE:01", channel=1, signal=-70)
            ap2 = AccessPoint(ssid="B", bssid="AA:BB:CC:DD:EE:02", channel=6, signal=-40)
            ap3 = AccessPoint(ssid="C", bssid="AA:BB:CC:DD:EE:03", channel=11, signal=-60)
            scanner.ap_list = {
                "AA:BB:CC:DD:EE:01": ap1,
                "AA:BB:CC:DD:EE:02": ap2,
                "AA:BB:CC:DD:EE:03": ap3,
            }
            sorted_aps = scanner.get_sorted_aps()
            assert sorted_aps[0].bssid == "AA:BB:CC:DD:EE:02"
            assert sorted_aps[1].bssid == "AA:BB:CC:DD:EE:03"
            assert sorted_aps[2].bssid == "AA:BB:CC:DD:EE:01"

    def test_get_sorted_aps_none_signal_last(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            ap1 = AccessPoint(ssid="A", bssid="AA:BB:CC:DD:EE:01", channel=1, signal=-40)
            ap2 = AccessPoint(ssid="B", bssid="AA:BB:CC:DD:EE:02", channel=6, signal=None)
            scanner.ap_list = {
                "AA:BB:CC:DD:EE:01": ap1,
                "AA:BB:CC:DD:EE:02": ap2,
            }
            sorted_aps = scanner.get_sorted_aps()
            assert sorted_aps[0].bssid == "AA:BB:CC:DD:EE:01"

    def test_get_clients_returns_clients(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            ap = AccessPoint(ssid="Test", bssid="AA:BB:CC:DD:EE:FF", channel=6, clients=["11:22:33:44:55:66", "77:88:99:AA:BB:CC"])
            scanner.ap_list["AA:BB:CC:DD:EE:FF"] = ap
            clients = scanner.get_clients("AA:BB:CC:DD:EE:FF")
            assert len(clients) == 2
            assert "11:22:33:44:55:66" in clients

    def test_get_clients_unknown_bssid(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            assert scanner.get_clients("unknown:bssid") == []

    def test_select_ap_valid_index(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            ap = AccessPoint(ssid="Test", bssid="AA:BB:CC:DD:EE:FF", channel=6)
            scanner.ap_list["AA:BB:CC:DD:EE:FF"] = ap
            result = scanner.select_ap([ap], 1)
            assert result is ap

    def test_select_ap_invalid_index(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            ap = AccessPoint(ssid="Test", bssid="AA:BB:CC:DD:EE:FF", channel=6)
            result = scanner.select_ap([ap], 99)
            assert result is None

    def test_stop_sets_event(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            assert scanner._stop_event.is_set() is False
            scanner.stop()
            assert scanner._stop_event.is_set() is True

    def test_display_aps_returns_aps(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            ap = AccessPoint(ssid="Test", bssid="AA:BB:CC:DD:EE:FF", channel=6, signal=-50, encryption="WPA2", clients=[])
            result = scanner.display_aps([ap])
            assert result == [ap]

    def test_display_aps_uses_sorted_when_none(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")
            ap = AccessPoint(ssid="Test", bssid="AA:BB:CC:DD:EE:FF", channel=6)
            scanner.ap_list["AA:BB:CC:DD:EE:FF"] = ap
            result = scanner.display_aps()
            assert len(result) == 1


class TestAPScannerExtractHelpers:
    def test_extract_channel_from_elt(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")

            mock_pkt = MagicMock()
            mock_elt = MagicMock()
            mock_elt.ID = 3
            mock_elt.info = b"\x06"
            mock_elt.payload = None

            mock_pkt.haslayer.return_value = True
            mock_pkt.getlayer.return_value = mock_elt

            channel = scanner._extract_channel(mock_pkt)
            assert channel == 6

    def test_extract_channel_dsset_fallback(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")

            mock_pkt = MagicMock()
            mock_pkt.haslayer.return_value = False
            mock_pkt.getlayer.return_value = None

            channel = scanner._extract_channel(mock_pkt)
            assert channel == 1

    def test_detect_encryption_wpa2(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")

            mock_pkt = MagicMock()
            mock_elt = MagicMock()
            mock_elt.ID = 48
            mock_elt.payload = None

            mock_pkt.haslayer.return_value = True
            mock_pkt.getlayer.return_value = mock_elt

            enc = scanner._detect_encryption(mock_pkt)
            assert enc == "WPA2"

    def test_detect_encryption_wpa(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")

            mock_pkt = MagicMock()
            mock_elt = MagicMock()
            mock_elt.ID = 221
            mock_elt.info = b"\x00\x50\xf2\x01test"
            mock_elt.payload = None

            mock_pkt.haslayer.return_value = True
            mock_pkt.getlayer.return_value = mock_elt

            enc = scanner._detect_encryption(mock_pkt)
            assert enc == "WPA"

    def test_detect_encryption_open(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")

            mock_pkt = MagicMock()
            mock_pkt.haslayer.return_value = False
            mock_pkt.getlayer.return_value = None

            enc = scanner._detect_encryption(mock_pkt)
            assert enc == "OPEN"

    def test_extract_signal(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")

            mock_pkt = MagicMock()
            # Production code calls pkt.getlayer(RadioTap); make that return
            # an object exposing dBm_AntSignal.
            mock_rt = MagicMock()
            mock_rt.dBm_AntSignal = 200
            mock_pkt.getlayer.return_value = mock_rt

            signal = scanner._extract_signal(mock_pkt)
            assert signal == -(256 - 200)

    def test_extract_signal_no_radiotap(self):
        with patch("core.scanner.sniff"):
            from core.scanner import APScanner
            scanner = APScanner("wlan0")

            mock_pkt = MagicMock()
            mock_pkt.haslayer.return_value = False

            signal = scanner._extract_signal(mock_pkt)
            assert signal is None