"""Contract test for core.paths — pin the centralised path module's
behavior so any future change shows up here.

Section 7 hygiene: every module that owns a directory layout should
have at least one smoke test asserting the computed paths actually
point at real on-disk locations.
"""

import os

from core.paths import (
    CONFIG_DIR,
    CORE_DIR,
    DEFAULT_LOG_FILE,
    DNSMASQ_PID_PATH,
    DOCS_DIR,
    HOSTAPD_PID_PATH,
    LOGS_DIR,
    PORTAL_STATIC_DIR,
    PORTAL_TEMPLATES_DIR,
    PROJECT_ROOT,
    ensure_config_dir,
    ensure_logs_dir,
)


def test_project_root_contains_expected_layout():
    # Top-level dirs every project must have.
    for expected in ("core", "portal", "tests", "utils"):
        assert os.path.isdir(os.path.join(PROJECT_ROOT, expected)), (
            f"{expected!r} should be a sibling of core/ — project root "
            f"appears to be wrong ({PROJECT_ROOT!r})"
        )


def test_core_dir_is_sibling_of_portal():
    # core/ must live AT the project root, not nested deeper.
    assert os.path.dirname(CORE_DIR) == PROJECT_ROOT


def test_portal_dirs_real():
    # Static + templates dirs exist on disk and contain their germane files.
    assert os.path.isdir(PORTAL_TEMPLATES_DIR)
    assert os.path.isdir(PORTAL_STATIC_DIR)
    assert os.path.isfile(os.path.join(PORTAL_TEMPLATES_DIR, "login.html"))
    assert os.path.isfile(os.path.join(PORTAL_STATIC_DIR, "style.css"))


def test_config_and_logs_dirs_are_absolute():
    for p in (CONFIG_DIR, LOGS_DIR, DOCS_DIR):
        assert os.path.isabs(p), f"{p!r} must be absolute"


def test_ensure_dirs_idempotent():
    # Calling twice must not raise; both must end up existing.
    ensure_logs_dir()
    ensure_logs_dir()
    ensure_config_dir()
    ensure_config_dir()
    assert os.path.isdir(LOGS_DIR)
    assert os.path.isdir(CONFIG_DIR)


def test_default_log_file_under_logs_dir():
    # The default credential-log path must be inside LOGS_DIR — a regression
    # guard for reviewers' pet peeve: "log file created at cwd by accident".
    assert os.path.dirname(DEFAULT_LOG_FILE) == LOGS_DIR
    assert DEFAULT_LOG_FILE.endswith(".jsonl")


def test_pid_paths_under_tmp():
    # PID files are conventionally in /tmp; just confirm the strings we
    # publish are the ones hostapd/dnsmasq will write to.
    for p in (HOSTAPD_PID_PATH, DNSMASQ_PID_PATH):
        assert p.startswith("/tmp/")
        assert p.endswith(".pid")
