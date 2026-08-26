"""Section 9: iptables backup+restore hardening tests.

Covers:
- ``backup_iptables`` writes expected JSON when iptables-save is mocked.
- ``restore_iptables`` replays the JSON through ``iptables-restore``.
- ``NetworkConfig.setup_iptables`` invokes ``backup_iptables`` BEFORE
  our own chains are installed (so the snapshot captures pre-attack
  state, not our own rules).
- ``NetworkConfig.cleanup`` invokes ``restore_iptables`` so unrelated
  chains the operator had before the run (docker / wireguard) come
  back.
- A corrupt JSON file is deleted by ``restore_iptables`` so the
  next call doesn't loop on the same dead file.
- A missing iptables-restore binary on the host makes
  ``restore_iptables`` fail-soft without raising.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from core.network import (
    _BACKUP_FILENAME,
    NetworkConfig,
    backup_iptables,
    restore_iptables,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_backup_path(tmp_path, monkeypatch):
    """Redirect ``_backup_path`` into a per-test tmp file."""
    target = tmp_path / _BACKUP_FILENAME
    monkeypatch.setattr("core.network._backup_path", lambda: str(target))
    return str(target)


def _good_save_payload() -> dict:
    """Sample iptables-save text — both tables, with a custom rule we'd want
    restored after the run."""
    return {
        "nat": (
            "*nat\n"
            ":PREROUTING ACCEPT [0:0]\n"
            ":POSTROUTING ACCEPT [0:0]\n"
            "-A POSTROUTING -o wg0 -j MASQUERADE\n"
            "COMMIT\n"
        ),
        "filter": ("*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -i docker0 -j ACCEPT\nCOMMIT\n"),
        # An attacker file might still be in here, but as long as JSON parses
        # we move on. (We use string values, not str inputs — the JSON
        # encoder objects to MagicMock traces from a poorly-patched test.)
    }


# ---------------------------------------------------------------------------
# backup_iptables
# ---------------------------------------------------------------------------


class TestBackupIptables:
    """When iptables-save runs successfully we should see a JSON dump."""

    @patch("subprocess.run")
    def test_writes_json_with_nat_and_filter(self, mock_run, fake_backup_path):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=_good_save_payload()["nat"]),
            MagicMock(returncode=0, stdout=_good_save_payload()["filter"]),
        ]
        assert backup_iptables() is True
        with open(fake_backup_path, encoding="utf-8") as f:
            data = json.load(f)
        assert "wg0" in data["nat"]
        assert "docker0" in data["filter"]

    @patch("subprocess.run")
    def test_skips_when_iptables_save_missing(self, mock_run, fake_backup_path):
        """No iptables-save on the host → return False, don't crash."""
        mock_run.side_effect = FileNotFoundError("iptables-save not found")
        assert backup_iptables() is False
        # And no garbage file left behind.
        import os as _os

        assert not _os.path.exists(fake_backup_path)

    @patch("subprocess.run")
    def test_records_soft_failure(self, mock_run, fake_backup_path):
        """Both saves returned non-zero → log warning, return False."""
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout=""),
            MagicMock(returncode=1, stdout=""),
        ]
        assert backup_iptables() is False


# ---------------------------------------------------------------------------
# restore_iptables
# ---------------------------------------------------------------------------


class TestRestoreIptables:
    """Restore replays the snapshot and survives malformed backups."""

    def test_no_backup_file_returns_false_without_error(self, fake_backup_path):
        """Missing file is a no-op (idempotent), not an exception."""
        assert restore_iptables() is False

    @patch("subprocess.run")
    def test_replays_blob_to_iptables_restore(
        self,
        mock_run,
        fake_backup_path,
    ):
        """End-to-end happy path: file present → iptables-restore invoked
        with the concatenated nat+filter blob."""
        with open(fake_backup_path, "w", encoding="utf-8") as f:
            json.dump(_good_save_payload(), f)

        mock_run.return_value = MagicMock(returncode=0, stderr="")

        assert restore_iptables() is True

        # Exactly one iptables-restore call. iptables-save is NOT re-run.
        mock_run.assert_called_once()
        call = mock_run.call_args
        assert call.args[0] == ["iptables-restore"]
        injected = (
            call.kwargs.get("input") or call.args[1] if len(call.args) > 1 else call.kwargs["input"]
        )
        assert "docker0" in injected
        assert "wg0" in injected

    @patch("subprocess.run")
    def test_iptables_restore_failure_returns_false_not_raises(
        self,
        mock_run,
        fake_backup_path,
    ):
        """Non-zero rc from iptables-restore → False (best-effort rollback)."""
        with open(fake_backup_path, "w", encoding="utf-8") as f:
            json.dump(_good_save_payload(), f)
        mock_run.return_value = MagicMock(returncode=1, stderr="bad rules")

        assert restore_iptables() is False

    def test_corrupt_json_is_deleted_no_retry_loop(self, fake_backup_path):
        """Malformed JSON: rollback must self-heal by removing the bad file."""
        with open(fake_backup_path, "w", encoding="utf-8") as f:
            f.write("{not json")
        # Don't even patch subprocess.run — corrupt JSON short-circuits before
        # we get there.
        with patch("subprocess.run"):
            assert restore_iptables() is False

        import os as _os

        assert _os.path.exists(fake_backup_path) is False, (
            "restore_iptables must self-heal corrupt backups to avoid looping"
        )

    @patch("subprocess.run", side_effect=FileNotFoundError("iptables-restore missing"))
    def test_no_iptables_restore_on_host_no_raises(self, mock_run, fake_backup_path):
        with open(fake_backup_path, "w", encoding="utf-8") as f:
            json.dump(_good_save_payload(), f)
        assert restore_iptables() is False


# ---------------------------------------------------------------------------
# NetworkConfig integration — rollout sequencing
# ---------------------------------------------------------------------------


class TestNetworkConfigRollback:
    """Confirm setup→backup is called BEFORE our chains; cleanup→restore."""

    @patch("core.network.restore_iptables", create=True)
    @patch("core.network.backup_iptables", create=True)
    @patch("subprocess.run")
    @patch("tempfile.NamedTemporaryFile")
    def test_setup_calls_backup(
        self,
        mock_temp,
        mock_run,
        mock_backup,
        mock_restore,
        tmp_path,
    ):
        """setup_iptables() must invoke backup_iptables() before our own
        iptables-restore pushes the NAT+filter templates — otherwise the
        backup would snapshot OUR work, not the host's pre-attack state."""
        mock_file = MagicMock()
        mock_file.name = "/tmp/rules.123"
        mock_temp.return_value.__enter__.return_value = mock_file
        mock_run.return_value = MagicMock(returncode=0)

        nc = NetworkConfig("eth0", "wlan0")
        assert nc.setup_iptables() is True

        mock_backup.assert_called_once()
        mock_restore.assert_not_called()  # restore must NOT happen during setup

    @patch("core.network.flush_iptables", create=True)
    @patch("core.network.restore_iptables", create=True)
    @patch("core.network.backup_iptables", create=True)
    def test_cleanup_calls_restore(
        self,
        _mock_backup,
        mock_restore,
        mock_flush,
    ):
        """cleanup() must invoke restore_iptables() AFTER our chains are
        flushed, so unrelated chains (e.g. docker) come back too."""
        nc = NetworkConfig("eth0", "wlan0")
        nc._granted_ips = {"10.0.0.25"}
        with patch.object(NetworkConfig, "disable_ip_forwarding"):
            nc.cleanup()

        mock_flush.assert_called_once()
        mock_restore.assert_called_once()
