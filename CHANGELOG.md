# Changelog

All notable changes to **wimirage** are documented here. The format
is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [1.0.0]

### Added
- Section 8: `requirements.lock` with hash-pinned versions, regenerated via
  `pip-compile`.
- Section 8: CI workflow now runs `pip-audit` (vulnerability audit) and
  `pip-licenses` (license compliance) as required checks.
- Section 8: `preflight.py` enforces the Python version range declared in
  `pyproject.toml` and verifies a default route is present.
- Section 7: weekly scheduled run of `mutmut` mutation testing + a
  lockfile-freshness check.
- Section 6: this `CHANGELOG.md`, plus `CONTRIBUTING.md`, `SECURITY.md`,
  and `docs/architecture.mermaid`.

### Changed
- **Security sweep (S-5 … S-8)** — second-pass hardening, building on
  the v2.0.0 + 5/5 baseline:
  - **S-5 PII scrub in route logs** — `portal/routes.py` now wraps every
    `logger.info(...)` call that touched a captured phone or email with
    `portal.security.scrub_for_log(...)`. A shared rotating-file audit
    log will no longer hold captured data in cleartext.
  - **S-6 cooperative-shutdown wiring** — `cli/menu.py` no longer
    shadows `utils.cleanup:shutdown_event` with a fresh `threading.Event`,
    which used to make SIGINT fall back to the 1.0 s wait tick. The
    canonical event is the single source of truth.
  - **S-7 hostapd config injection resistance** — `RogueAP._generate_hostapd_config`
    strips `\n` and `\r` from the SSID before rendering the config so a
    payload SSID can't smuggle additional hostapd directives into the
    generated file.
  - **S-8 interface-name validation** — `MenuHandler.do_captive_portal`,
    `do_network_routing`, and `_select_interfaces_for_chain` now regex
    the operator's iface-name input against `^[A-Za-z0-9_.:-]{1,16}$`
    before passing it to `subprocess.run` (no more shell-meta vectors).
- New regression file `tests/test_security_sweep_s5_s8.py` (13 tests)
  pins the contracts above.

### Fixed
- Section 8: `[tool.ruff]` deprecated `select`/`ignore` migrated to
  `[tool.ruff.lint]`.
- Section 8: pyproject `[all]` extra now references the real
  `[sms,encrypt,dev]` extras (was `[twilio,dev]` — `twilio` extra did
  not exist).

---

## [2.0.0] — 2026-06-17

> **Heads-up:** Section-1-through-5 correctness and hardening pass. Most
> public APIs are stable; several logging routes moved (`print` → `logger`)
> and the Flask app is now constructed via a DI-friendly
> `build_portal_blueprint(...)` factory.

### Added
- **Code Quality** (Section 1):
  - `_all_` on `core/`, `utils/`, `portal/`, and `main.py`.
  - Google-style docstrings on every public class and method.
  - `do_full_chain()` decomposed into `_wait_for_deauth`,
    `_launch_rogue_ap`, `_configure_network`, `_launch_portal`.
  - `NAT_TABLE_TEMPLATE` / `FILTER_TABLE_TEMPLATE` replace the
    previously-inlined iptables magic strings.
- **Architecture** (Section 2):
  - `portal/routes.py` extracted the Flask routes into a parameterised
    `Blueprint`. `CaptivePortal` is now a thin aggregator.
  - `AttackContext.__init__(logger_instance=None)` accepts a pre-built
    `CredentialLogger`.
  - `AttackState.FULL_ATTACK -> PORTAL_RUNNING` is now allowed.
  - `APScanner.scan()` returns a structured `ScanResult(aps, duration,
    packet_count)`.
  - `AppConfig.load(path)` reads YAML/TOML files using `dataclasses.replace`.
  - `EventBus.emit` logs handler exceptions.
- **Security** (Section 3):
  - CSP tightened to drop `'unsafe-inline'` for `script-src` /
    `style-src`.
  - Per-request `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE=Lax`,
    conditional `SESSION_COOKIE_SECURE` (only when `ssl_context` is set).
  - Flask `MAX_CONTENT_LENGTH = 1 MB`.
  - `secret_key` auto-generates an ephemeral `secrets.token_hex(32)`
    when left at the default.
  - Country-code validation against `VALID_COUNTRY_CODES` returns 400.
  - Twilio credentials read into env vars; `getpass.getpass` confirmed
    twice.
  - `RotatingFileHandler(maxBytes=10MB, backupCount=5)` for `audit.log`.
- **Error Handling** (Section 4):
  - `sys.excepthook` + `threading.excepthook` both installed in `main()`.
  - `@retry(max_attempts, delay, exceptions)` decorator in
    `utils/cleanup.py` applied to `restore_interfaces`.
  - `ProcessManager._watch_one()` per-process watchdog; `register()` can
    now accept `restart=True, restart_callback=...`.
  - hostapd/dnsmasq launched with `-P /tmp/<name>.pid` to close the
    TOCTOU poll race.
  - `_read_stderr_log` returns `""` (not `None`).
  - Flask runs with `request_timeout=30`.
  - `do_full_chain` uses a `threading.Event` for shutdown instead of a
    busy-wait.
  - `grant_internet` checks `subprocess.run` return code.
- **Performance** (Section 5):
  - deauth loop uses `time.perf_counter()` for drift-free PPS.
  - BPF filter includes `or type data` (kernel-side data-frame
    filtering).
  - `_packet_handler` enqueues into `queue.Queue`; a batch worker
    drains `_PACKET_BATCH_SIZE=100` packets per invocation.
  - `CredentialLogger` buffers writes behind a Lanflush worker (10
    entries / 5 s).
  - `get_sorted_aps` cached and invalidated on update.
  - `TwilioOTPService.__init__` builds the twilio `Client` once.

### Changed
- `RogueAP` modules per-method helper signatures stayed compatible; the
  one behavioural change is that `_read_stderr_log` no longer returns
  `None`.
- `main.py` logging hooks no longer call `print` for non-UX messages.

### Deprecated
- None.

### Removed
- `core.models.ClientInfo` (unused).
- Hardcoded `core.scanner` print statements (moved to logger).

### Fixed
- `core.scanner` BPF filter now matches the range of frames the parser
  handles.
- `RogueAP` hostapd/dnsmasq startup race closed via PID file.

---

## [1.0.0] — 2025-11-04

- Initial release.
- APScanner, Deauth, Rogue AP, Captive Portal, OTP service, JSONL
  credential logger. Single-screen interactive CLI.
