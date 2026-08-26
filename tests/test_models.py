from core.models import AccessPoint, AppConfig, AttackState, Credential


class TestAttackState:
    def test_attack_state_enum_values(self):
        assert AttackState.IDLE.value is not None
        assert AttackState.SCANNING.value is not None
        assert AttackState.SCANNED.value is not None
        assert AttackState.TARGET_SELECTED.value is not None
        assert AttackState.DEAUTH_RUNNING.value is not None
        assert AttackState.AP_RUNNING.value is not None
        assert AttackState.PORTAL_RUNNING.value is not None
        assert AttackState.FULL_ATTACK.value is not None

    def test_attack_state_count(self):
        assert len(AttackState) == 8


class TestAccessPoint:
    def test_access_point_creation(self, sample_ap):
        assert sample_ap.ssid == "TestNetwork"
        assert sample_ap.bssid == "AA:BB:CC:DD:EE:FF"
        assert sample_ap.channel == 6
        assert sample_ap.signal == -45
        assert sample_ap.encryption == "WPA2"
        assert sample_ap.clients == ["11:22:33:44:55:66"]

    def test_access_point_default_values(self):
        ap = AccessPoint(ssid="Hidden", bssid="00:11:22:33:44:55", channel=1)
        assert ap.signal is None
        assert ap.encryption == "OPEN"
        assert ap.clients == []

    def test_access_point_clients_mutable(self, sample_ap):
        sample_ap.clients.append("77:88:99:AA:BB:CC")
        assert len(sample_ap.clients) == 2


class TestCredential:
    def test_credential_creation(self, sample_credential):
        assert sample_credential.timestamp == "2026-06-17 12:00:00"
        assert sample_credential.client_ip == "10.0.0.25"
        assert sample_credential.phone == "+919876543210"
        assert sample_credential.email == "test@example.com"
        assert sample_credential.stage == "otp_verified"

    def test_credential_optional_fields(self):
        cred = Credential(timestamp="2026-06-17 12:00:00", client_ip="10.0.0.1")
        assert cred.phone is None
        assert cred.email is None
        assert cred.otp is None
        assert cred.stage == "unknown"


class TestAppConfig:
    def test_app_config_defaults(self):
        config = AppConfig()
        assert config.gateway == "10.0.0.1"
        assert config.dhcp_range == "10.0.0.2,10.0.0.100"
        assert config.portal_port == 80
        assert config.scan_timeout == 20
        assert config.deauth_pps == 100
        assert config.otp_length == 6
        assert config.otp_expiry_seconds == 300
        assert config.otp_max_attempts == 5
        assert config.otp_lockout_seconds == 600
        assert config.rate_limit_per_minute == 5
        assert config.secret_key == "change-me-in-production"
        assert config.encrypted_logs is False

    def test_app_config_custom(self, app_config):
        assert app_config.portal_port == 8080
        assert app_config.secret_key == "test-secret-key-12345"
        assert app_config.rate_limit_per_minute == 10
