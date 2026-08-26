"""Tests for ``cli._logging`` (banner / logger / root-check)."""

from __future__ import annotations

import logging
import os

import pytest

from cli import _logging


class TestBanner:
    def test_banner_is_no_foreign_scripts(self):
        """The banner must NOT contain Sanskrit / Devanagari or any
        other non-Latin script — u explicitly asked for English-only
        ASCII art.  Box-drawing / block chars (U+2500–U+259F) are fine.
        """
        for ch in _logging.BANNER:
            cp = ord(ch)
            # Allow printable ASCII + Latin-1 Supplement + box-drawing;
            # reject everything else (Devanagari U+0900-U+097F, Han,
            # Hangul, etc.).
            if cp < 0x20 or cp == 0x7F:
                continue  # control / whitespace
            if cp < 0xB0 or (0x2500 <= cp <= 0x259F):
                continue  # Latin-1 printable, ASCII printable, block art
            assert False, f"non-Latin char {ch!r} (U+{cp:04X}) found in BANNER"

    def test_banner_includes_authorized_use_only(self):
        """Compliance guardrail: visible text signals legal scope."""
        assert "authorized use only" in _logging.BANNER

    def test_banner_declares_toolkit(self):
        """Helpful on first run: tells the operator what they're
        launching without forcing them to read README."""
        assert "Wi-Fi" in _logging.BANNER
        assert "Toolkit" in _logging.BANNER

    def test_disclaimer_explicit(self):
        """DISCLAIMER carries the legal warning in plain English."""
        assert "DISCLAIMER" in _logging.DISCLAIMER
        assert "penetration testing" in _logging.DISCLAIMER


class TestConfigureLogging:
    def test_returns_named_logger(self):
        log = _logging.configure_logging()
        assert isinstance(log, logging.Logger)
        assert log.name == "wimirage"

    @pytest.fixture
    def fresh_logger(self):
        """Strip handlers before reconfigured so each call is isolated."""
        named = logging.getLogger("wimirage")
        named.handlers = []
        yield named
        named.handlers = []

    def test_idempotent_handler_addition(self, fresh_logger, tmp_path):
        """Configuring twice does not double-stack file handlers."""
        os.environ["LOGS_DIR"] = str(tmp_path)
        log1 = _logging.configure_logging()
        n_before = len(log1.handlers)
        log2 = _logging.configure_logging()
        n_after = len(log2.handlers)
        # At most one RotatingFileHandler + one StreamHandler
        assert n_after <= 2
        assert n_after >= n_before  # never shrinks

    def test_handlers_include_filehandler(self, tmp_path):
        os.environ["LOGS_DIR"] = str(tmp_path)
        log = _logging.configure_logging()
        # RotatingFileHandler is the only file handler in the stack
        from logging.handlers import RotatingFileHandler

        assert any(isinstance(h, RotatingFileHandler) for h in log.handlers)


class TestCheckRoot:
    def test_skips_on_non_posix(self, monkeypatch):
        """On platforms without ``os.geteuid`` (Windows / WSL tests) the
        helper must be a no-op. Regression guard."""
        monkeypatch.delattr("os.geteuid", raising=False)
        # Must not raise
        _logging.check_root()
