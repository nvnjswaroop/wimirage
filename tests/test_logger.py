import json

from core.models import Credential
from utils.logger import CredentialLogger


class TestCredentialLogger:
    def test_log_credential_creates_file(self, tmp_path):
        log_file = tmp_path / "creds.jsonl"
        logger = CredentialLogger(log_file=str(log_file))
        logger.log_credential(
            client_ip="10.0.0.25",
            phone="+919****3210",
            email="test@example.com",
            stage="otp_verified",
        )
        logger.flush_now()  # sync the async flush before asserting
        assert log_file.exists()

    def test_log_credential_writes_jsonl_line(self, tmp_path):
        log_file = tmp_path / "creds.jsonl"
        logger = CredentialLogger(log_file=str(log_file))
        logger.log_credential(
            client_ip="10.0.0.25",
            phone="+919****3210",
            email="test@example.com",
            stage="phone_email_submitted",
        )
        logger.flush_now()

        with open(log_file) as f:
            line = f.readline().strip()
        data = json.loads(line)
        assert data["client_ip"] == "10.0.0.25"
        assert data["phone"] == "+919****3210"
        assert data["email"] == "test@example.com"
        assert data["stage"] == "phone_email_submitted"

    def test_log_credential_multiple_entries_jsonl(self, tmp_path):
        log_file = tmp_path / "creds.jsonl"
        logger = CredentialLogger(log_file=str(log_file))
        logger.log_credential(
            client_ip="10.0.0.1",
            phone="+919****3210",
            email="a@test.com",
            stage="phone_email_submitted",
        )
        logger.log_credential(
            client_ip="10.0.0.2", phone="+919****3211", email="b@test.com", stage="otp_verified"
        )
        logger.flush_now()

        with open(log_file) as f:
            lines = [json.loads(line.strip()) for line in f if line.strip()]
        assert len(lines) == 2
        assert lines[0]["client_ip"] == "10.0.0.1"
        assert lines[1]["client_ip"] == "10.0.0.2"

    def test_log_credential_loads_existing(self, tmp_path):
        log_file = tmp_path / "creds.jsonl"
        logger1 = CredentialLogger(log_file=str(log_file))
        logger1.log_credential(
            client_ip="10.0.0.25", phone="+919****3210", email="test@example.com"
        )
        logger1.flush_now()  # ensure the line is on disk before logger2 reads it

        logger2 = CredentialLogger(log_file=str(log_file))
        assert len(logger2.credentials) == 1

    def test_log_credential_invalid_stage_defaults_to_unknown(self, tmp_path):
        log_file = tmp_path / "creds.jsonl"
        logger = CredentialLogger(log_file=str(log_file))
        logger.log_credential(client_ip="10.0.0.1", stage="invalid_stage")
        assert logger.credentials[0].stage == "unknown"

    def test_display_summary_no_error(self, tmp_path, capsys):
        log_file = tmp_path / "creds.jsonl"
        logger = CredentialLogger(log_file=str(log_file))
        logger.log_credential(
            client_ip="10.0.0.1", phone="+919876543210", email="a@test.com", stage="otp_verified"
        )
        logger.display_summary()
        captured = capsys.readouterr()
        assert "CAPTURE SUMMARY" in captured.out
        assert "Total entries" in captured.out

    def test_display_all_empty(self, tmp_path, capsys):
        log_file = tmp_path / "creds.jsonl"
        logger = CredentialLogger(log_file=str(log_file))
        logger.display_all()
        captured = capsys.readouterr()
        assert "No credentials" in captured.out

    def test_get_all(self, tmp_path):
        log_file = tmp_path / "creds.jsonl"
        logger = CredentialLogger(log_file=str(log_file))
        logger.log_credential(
            client_ip="10.0.0.1", phone="+919876543210", stage="phone_email_submitted"
        )
        all_creds = logger.get_all()
        assert len(all_creds) == 1
        assert isinstance(all_creds[0], Credential)
