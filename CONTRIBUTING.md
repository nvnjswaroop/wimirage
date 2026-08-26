# Contributing to wimirage

First, **read `SECURITY.md` and the disclaimer at the top of `README.md`
before contributing.** This is offensive security software; contributions
that lower guardrails, weaken logging, or remove safeguards will be
rejected. Code is reviewed for safety as much as for function.

This guide describes how to set up a development environment, run the
test suite, and submit a pull request.

---

## Table of contents

1. [Legal posture](#legal-posture)
2. [Development setup](#development-setup)
3. [Project layout](#project-layout)
4. [Coding style](#coding-style)
5. [Running the test suite](#running-the-test-suite)
6. [Submitting a pull request](#submitting-a-pull-request)
7. [PR template](#pr-template)

---

## Legal posture

- This project is for **authorised penetration testing**. By submitting a
  pull request you confirm you are not contributing code intended to
  facilitate attacks on networks you do not own or lack written
  permission to test.
- Maintainers reserve the right to reject any contribution that weakens
  the existing safety rails (audit logging, rate limiting, CSP
  hardening, etc.) without regression tests justifying the change.

---

## Development setup

### Requirements

- Linux (Kali rolling recommended; Ubuntu 22.04 / Debian 12 also work).
- Python 3.8 .. 3.12.
- Two Wi-Fi adapters if you plan to exercise the live attack path.
  Most contributors can do impactful work on a single-machine dev setup
  by running the unit tests only.

### Bootstrap

```bash
git clone https://example.invalid/wimirage && cd wimirage

# Create a venv
python3 -m venv .venv
source .venv/bin/activate

# Install with every extra
pip install -e ".[sms,encrypt,dev]"

# Optional: regenerate requirements.lock if you updated pyproject.toml
pip install pip-tools
pip-compile --quiet --generate-hashes -o requirements.lock pyproject.toml
```

### System packages

```bash
sudo apt-get update && sudo apt-get install -y \
    hostapd dnsmasq aircrack-ng iw wireless-tools \
    net-tools iptables python3-venv
```

### Sanity check

```bash
sudo python3 preflight.py   # verifies binaries, Python version, default route
pytest -m "not slow"        # unit tests, no live network needed
```

---

## Project layout

```
Wifi-project/
├── main.py                 # CLI orchestrator + MenuHandler
├── preflight.py            # system-requirements check
├── pyproject.toml          # package metadata, ruff/mypy/pytest config
├── setup.py                # legacy setuptools shim (delegates to pyproject.toml)
├── requirements.txt        # runtime deps (with extras pointer)
├── requirements-dev.txt    # test/lint/type/audit/mutation deps
├── requirements.lock       # pip-tools-compiled, hash-pinned for reproducibility
├── Dockerfile              # cali-rolling:2024.2 base image
├── .env.example            # environment template (copy to .env to source)
├── core/                   # domain logic (scanner, deauth, rogue_ap, network, …)
│   ├── models.py           # dataclasses + enums
│   ├── events.py           # EventBus
│   ├── process_manager.py  # ProcessManager + watchdog
│   ├── scanner.py          # APScanner
│   ├── deauth.py           # DeauthAttack
│   ├── rogue_ap.py         # RogueAP
│   ├── network.py          # NetworkConfig (iptables)
│   ├── captive_portal.py   # CaptivePortal (Flask aggregator)
│   ├── otp_service.py      # OTPServiceInterface + Demo / Twilio impls
│   └── __init__.py
├── portal/                 # HTTP layer
│   ├── routes.py           # Flask Blueprint factory
│   ├── templates/
│   └── static/
├── utils/                  # host-OS helpers
│   ├── monitor_mode.py
│   ├── logger.py           # CredentialLogger (JSONL, optional Fernet)
│   └── cleanup.py          # Cleanup + signal handlers
├── tests/                  # pytest suite
├── docs/                   # architecture.mermaid
├── config/                 # generated hostapd/dnsmasq configs (gitignored)
└── logs/                   # captured credentials + audit log (gitignored)
```

### Module boundaries

- **`core/`** — no I/O outside Scapy, `subprocess`, and Flask. Pure domain
  logic with DI-friendly constructors (no implicit globals).
- **`utils/`** — adapters for host OS (monitor mode, JSONL, signal
  handling). All subprocess calls fail-soft.
- **`portal/`** — Flask-specific. Cannot import from `core/` at module
  top level (avoid circular import; routes.py imports the helpers
  lazily inside its factory function).
- **`main.py`** — orchestrates everything; owns `AttackContext` and the
  menu loop.

---

## Coding style

- **Python 3.8-compatible**. The codebase declares
  `requires-python = ">=3.8,<3.13"`; no walrus-abusing one-liners that
  Py3.8 can't parse.
- **Google-style docstrings** on every public class and method.
- **Type annotations** on every public function argument and return.
- **`__all__`** on every refactorable module.
- **No `print()` for non-UX messages** — `logger.{info,warning,error}`.
  UX-only stdout (banner, menus, captor table) may keep `print`.
- **No silent `except Exception: pass`.** Either log the exception or
  re-raise; bare `pass` is reserved for `KeyboardInterrupt`-like signal
  paths.
- **New subprocess calls** must include a `timeout` and a `try/except`
  that catches `subprocess.TimeoutExpired` + `FileNotFoundError`.
- **Tests must accompany behavioural changes.** If you change the shape
  of `AttackState.can_transition`, the `tests/test_state_machine.py`
  suite is required to grow with you.

### Lint + format

```bash
ruff check core/ utils/ portal/ main.py preflight.py
ruff format --check core/ utils/ portal/ main.py preflight.py
mypy core/ utils/
```

`ruff` is the source of truth for style. `mypy` is informational only
for now (`--ignore-missing-imports`).

---

## Running the test suite

```bash
# Default unit suite (no slow/integration markers)
pytest -m "not slow"

# With coverage
pytest --cov=core --cov=utils --cov=portal --cov-fail-under=65

# Just the slow/integration tests
pytest -m slow
pytest -m integration

# Mutation testing (slow, run weekly in CI)
pip install mutmut
mutmut run --paths-to-mutate=core/
mutmut results
```

Coverage threshold is enforced at **65%** in CI. New modules should land
above that line; if a hard-to-test file drags the average down, open a
follow-up issue rather than gating the PR.

---

## Submitting a pull request

1. **Branch from `main`.** Use a descriptive name:
   `feature/issue-123-state-machine-tightening`,
   `fix/cleanup-sigint-handler-regression`, etc.
2. **One logical change per PR.** Split if you have multiple
   unrelated fixes.
3. **Conventional Commits** for the squash-merge title:
   `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `chore:`.
4. **Update `CHANGELOG.md`** under the `[Unreleased]` heading.
5. **Pre-commit checklist**:
   - [ ] `ruff check` passes
   - [ ] `ruff format --check` passes
   - [ ] `pytest -m "not slow"` passes
   - [ ] coverage threshold (65%) holds
   - [ ] `mypy core/ utils/` has no new errors
   - [ ] New public functions have docstrings + `__all__` updates
   - [ ] Behavioural changes ship with tests
6. **Push your branch and open a PR.** Fill in the template below.

Reviewers will focus on:

- Did you regress any safety rail?
- Are the tests actually checking the change?
- Is the public API change documented?

---

## PR template

```markdown
## What changed

<!-- 1–3 sentences. -->

## Why

<!-- Link the issue / motivation. -->

## How to test

<!-- Exact commands + expected output. Include manual reproduction for live
     attack-path changes. -->

## Safety impact

- [ ] No safeguard was removed.
- [ ] No new codepath bypasses audit logging.
- [ ] No new dependency added without a license that passes the CI
      compliance check.

## Checklist

- [ ] `ruff check` passes
- [ ] `ruff format --check` passes
- [ ] `pytest -m "not slow"` passes
- [ ] New tests added for behaviour changes
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
```
