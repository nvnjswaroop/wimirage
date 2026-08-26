#!/usr/bin/env python3
"""Pre-flight system check for wimirage.

Verifies:
  - Section 8 #5: Python version is within ``requires-python`` declared
    in ``pyproject.toml``.
  - All required CLI binaries are on PATH.
  - Required Python packages are importable.
  - Section 8 #6: an internet-facing interface has a default route.
  - The process is running with privileges required to manipulate
    interfaces / iptables.

Returns 0 on success, 1 if any required check fails.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import os
import re
from typing import Iterable


# Required CLI binaries. ``airmon-ng`` is optional — many users have
# iwconfig / iw and don't need the aircrack-ng wrapper.
REQUIRED_BINARIES = [
    "hostapd",
    "dnsmasq",
    "iwconfig",
    "iw",
    "ip",
    "iptables",
    "iptables-restore",
    "killall",
    "dhclient",
]

OPTIONAL_BINARIES = [
    "airmon-ng",     # only needed as fallback when iwconfig fails
]

# cryptography is optional — only required when encrypted_logs=True.
REQUIRED_PYTHON_PACKAGES = [
    "scapy",
    "flask",
    "jinja2",
]

OPTIONAL_PYTHON_PACKAGES = [
    "cryptography",  # only needed for [encrypt] extra
    "twilio",        # only needed for [sms] extra
]

# Section 8 #5: pulled from pyproject.toml's `requires-python` so we have
# one source of truth. Falls back to a sane default if parsing fails.
# IMPORTANT: keep these in sync with [project.requires-python] in
# pyproject.toml — `(3, 10)` to `(3, 14)` (exclusive upper).
MIN_PYTHON = (3, 10)
MAX_PYTHON = (3, 14)  # exclusive upper bound (matches pyproject "<3.14")


def _load_python_version_constraint() -> tuple[tuple[int, int], tuple[int, int]]:
    """Read ``requires-python`` from ``pyproject.toml``.

    Returns:
        ``(min_tuple, max_tuple)``. Both bounds are exclusive on the right
        edge: ``>=min``, ``<max``.
    """
    candidates = [
        os.path.join(os.path.dirname(__file__), "pyproject.toml"),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "pyproject.toml"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            try:
                import tomllib  # py3.11+
            except ImportError:  # pragma: no cover
                try:
                    import tomli as tomllib  # type: ignore
                except ImportError:
                    return MIN_PYTHON, MAX_PYTHON
            with open(path, "rb") as f:
                data = tomllib.load(f)
            spec = data.get("project", {}).get("requires-python", "")
            m = re.match(r">=(\d+)\.(\d+)(?:,<(\d+)\.(\d+))?", spec)
            if m:
                lo = (int(m.group(1)), int(m.group(2)))
                hi = (int(m.group(3)) if m.group(3) else 99,
                      int(m.group(4)) if m.group(4) else 0)
                if hi == (99, 0):
                    hi = MAX_PYTHON
                return lo, hi
            return MIN_PYTHON, MAX_PYTHON
    return MIN_PYTHON, MAX_PYTHON


def check_binary(name: str) -> bool:
    """Return True and print status if ``name`` is on PATH."""
    path = shutil.which(name)
    if path:
        print(f"  [OK] {name}: {path}")
        return True
    print(f"  [MISSING] {name}")
    return False


def check_python_package(name: str) -> bool:
    """Return True and print status if ``name`` is importable."""
    try:
        __import__(name)
        print(f"  [OK] {name}")
        return True
    except ImportError:
        print(f"  [MISSING] {name}")
        return False


def check_python_version() -> bool:
    """Section 8 #5."""
    lo, hi = _load_python_version_constraint()
    here = sys.version_info[:2]
    if lo <= here < hi:
        print(f"  [OK] Python {here[0]}.{here[1]} (constraint >={lo[0]}.{lo[1]}, <{hi[0]}.{hi[1]})")
        return True
    print(f"  [FAIL] Python {here[0]}.{here[1]} — needs >={lo[0]}.{lo[1]}, <{hi[0]}.{hi[1]}")
    return False


def check_default_route() -> bool:
    """Section 8 #6: confirm at least one default route exists.

    A missing default route means clients granted internet access via
    ``grant_internet`` would never reach the upstream — fail loudly.
    """
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            print(f"  [FAIL] 'ip route show default' exited {result.returncode}")
            return False
        routes = [ln for ln in result.stdout.splitlines() if ln.strip()]
        if not routes:
            print("  [FAIL] No default route. Pool: configure an internet-facing interface.")
            return False
        for r in routes:
            print(f"  [OK] {r}")
        return True
    except FileNotFoundError:
        print("  [FAIL] 'ip' command not found.")
        return False
    except subprocess.TimeoutExpired:
        print("  [FAIL] Timeout checking default route.")
        return False
    except (OSError, subprocess.SubprocessError) as e:
        print(f"  [FAIL] Error checking default route: {type(e).__name__}: {e}")
        return False


def _check_category(name: str, items: Iterable[str], checker) -> tuple[bool, bool]:
    """Run ``checker`` over ``items``; return (category_ok, all_ok)."""
    print(f"\n[*] Checking {name}...")
    category_ok = True
    for item in items:
        if not checker(item):
            category_ok = False
    if category_ok:
        print(f"\n[+] All {name} found.")
    return category_ok, False if not category_ok else category_ok


def main() -> int:
    print("=" * 60)
    print("  Wimirage - System Requirements Check")
    print("=" * 60)

    all_ok = True

    # 1) Python version (Section 8 #5)
    print("\n[*] Checking Python version...")
    py_ok = check_python_version()
    all_ok = all_ok and py_ok

    # 2) System binaries
    binaries_ok, _ = _check_category("system binaries", REQUIRED_BINARIES, check_binary)
    all_ok = all_ok and binaries_ok

    print("\n[*] Checking optional binaries...")
    for b in OPTIONAL_BINARIES:
        if shutil.which(b):
            print(f"  [OK] {b}: {shutil.which(b)}")
        else:
            print(f"  [INFO] {b} missing — will fall back to iwconfig")

    # 3) Required Python packages
    py_pkgs_ok, _ = _check_category(
        "Python packages", REQUIRED_PYTHON_PACKAGES, check_python_package
    )
    all_ok = all_ok and py_pkgs_ok

    print("\n[*] Checking optional Python packages...")
    for pkg in OPTIONAL_PYTHON_PACKAGES:
        if check_python_package(pkg):
            pass  # informational
        else:
            print(f"  [INFO] {pkg} missing — install the [{pkg}] extra if you need it")

    # 4) Network interfaces (informational + warning if too few)
    print("\n[*] Checking network interfaces...")
    try:
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            interfaces = [
                line.split(":")[1].strip() for line in result.stdout.split("\n") if ":" in line
            ]
            print(f"  Found interfaces: {', '.join(interfaces)}")
            if len(interfaces) < 2:
                print(f"  [!] Warning: Only {len(interfaces)} interface(s) found. Two recommended.")
        else:
            print("  [!] Could not enumerate interfaces.")
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as e:
        print(f"  [!] Error checking interfaces: {type(e).__name__}: {e}")

    # 5) Section 8 #6 — default route
    print("\n[*] Checking internet connectivity (default route)...")
    route_ok = check_default_route()
    all_ok = all_ok and route_ok

    # 6) Root privileges
    print("\n[*] Checking root privileges...")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("  [OK] Running as root")
    else:
        print("  [!] Not running as root. Some features will fail.")
        all_ok = False

    print("\n" + "=" * 60)
    if all_ok:
        print("  [+] All checks passed! Ready to run.")
        print("=" * 60)
        return 0
    else:
        print("  [!] Some checks failed. Install missing dependencies.")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
