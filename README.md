# Wimirage

A professional Wi-Fi deauthentication and Evil Twin access point tool for **authorized penetration testing**. Operates in two phases: deauthentication of target clients, then deployment of a rogue AP with a captive portal to harvest credentials (phone numbers, email addresses) via OTP verification.

> **For authorized testing only. Unauthorized use is illegal.**

---

## Features

- **AP Scanner** — Discover nearby Wi-Fi networks with SSID, BSSID, channel, signal strength, encryption type, and connected clients
- **Deauth Attack** — Broadcast or targeted 802.11 deauthentication with configurable packets-per-second
- **Evil Twin AP** — Rogue access point cloning the target SSID/channel with hostapd + dnsmasq
- **Captive Portal** — Professional login page requesting phone number and email, with OTP verification
- **OTP Verification** — Demo mode (console OTP) or Twilio SMS integration
- **Credential Logging** — JSONL format with encryption support
- **State Machine** — Validates attack flow order
- **Event System** — Pluggable event bus for extensions
- **Security** — CSRF tokens, rate limiting, server-side input validation, security headers, OTP brute-force lockout
- **Clean Architecture** — Data models, dependency injection, process manager, event bus

---

## Requirements

| Requirement | Details |
|-------------|---------|
| OS | Linux (Kali Linux recommended) |
| Python | 3.8+ |
| Wi-Fi Adapters | 2x adapters with monitor + AP mode support |
| Root | Required (sudo) |

### System Dependencies

```bash
sudo apt install hostapd dnsmasq aircrack-ng iw wireless-tools net-tools iptables
```

---

## Quick Start

### 1. Install Dependencies

```bash
sudo apt update && sudo apt install -y hostapd dnsmasq aircrack-ng iw wireless-tools net-tools iptables
pip3 install -r requirements.txt
```

### 2. Verify System

```bash
sudo python3 preflight.py
```

### 3. Run

```bash
sudo python3 main.py
```

### 4. Run Full Attack Chain

Select **Option 7** from the menu for a fully automated attack.

---

## Usage Modes

### Interactive Menu

```
1. Scan for Access Points
2. Select Target AP
3. Start Deauth Attack
4. Launch Evil Twin (Rogue AP)
5. Start Captive Portal
6. Configure Network Routing
7. Run Full Attack Chain        <-- recommended
8. View Captured Credentials
9. Stop All
0. Exit
```

### OTP Service Options

| Option | Description |
|--------|-------------|
| `d` | Demo mode — OTP printed to terminal |
| `t` | Twilio — real SMS delivery |
| `n` | None — auto-verifies all submissions |

### Environment Variables (Twilio)

```bash
export TWILIO_SID="AC..."
export TWILIO_TOKEN="your_token"
export TWILIO_PHONE="+1234567890"
```

---

## Project Structure

```
Wifi-project/
├── main.py                  # CLI orchestrator + MenuHandler
├── preflight.py              # System requirements checker
├── pyproject.toml            # Package configuration
├── requirements.txt          # Python dependencies
├── requirements-dev.txt      # Development dependencies
├── Dockerfile                # Docker image
├── core/
│   ├── models.py             # AccessPoint, Credential, AppConfig, AttackState
│   ├── events.py             # EventBus
│   ├── process_manager.py    # ProcessManager
│   ├── scanner.py            # APScanner (Scapy-based)
│   ├── deauth.py             # DeauthAttack (Scapy-based)
│   ├── rogue_ap.py           # RogueAP (hostapd + dnsmasq)
│   ├── network.py            # NetworkConfig (iptables)
│   ├── captive_portal.py     # CaptivePortal (Flask)
│   └── otp_service.py         # BaseOTPService, DemoOTPService, TwilioOTPService
├── portal/
│   ├── templates/             # login.html, otp.html, success.html
│   └── static/               # style.css, script.js
├── utils/
│   ├── monitor_mode.py       # MonitorMode (iwconfig/airmon-ng)
│   ├── logger.py             # CredentialLogger (JSONL)
│   └── cleanup.py            # Cleanup + signal handlers
├── tests/                    # pytest test suite
├── config/                   # Generated hostapd/dnsmasq configs (runtime)
└── logs/                     # Captured credentials + audit log
```

---

## Security Features

| Feature | Details |
|---------|---------|
| CSRF Protection | Per-session tokens on all forms |
| Rate Limiting | Per-IP limits on all routes |
| Server-side Validation | Email/phone validated server-side with regex |
| OTP Brute-force Protection | 5 attempts max, 10-min lockout |
| Security Headers | X-Frame-Options, CSP, X-Content-Type-Options, etc. |
| Encrypted Log Storage | Optional Fernet encryption for credentials |
| Secret Key | Flask sessions use configurable secret key |
| getpass for Tokens | Twilio credentials not echoed to terminal |

---

## Development

### Install Dev Dependencies

```bash
pip install -r requirements-dev.txt
```

### Run Tests

```bash
pytest tests/ -v
pytest tests/ --cov=core --cov=utils --cov-report=html
```

### Lint

```bash
ruff check core/ utils/
mypy core/ utils/
```

### Docker

```bash
docker build -t wifi-eviltwin .
docker run --privileged -it wifi-eviltwin
```

---

## Configuration

All configurable values live in `core/models.py` via the `AppConfig` dataclass. Override defaults programmatically:

```python
from core.models import AppConfig
from core.captive_portal import CaptivePortal

config = AppConfig()
config.portal_port = 8443
config.secret_key = "your-secure-random-key"
config.encrypted_logs = True
config.otp_max_attempts = 3

portal = CaptivePortal(config=config, otp_service=my_otp_service)
```

---

## Extending

### Custom OTP Service

```python
from core.otp_service import OTPServiceInterface

class MyOTPService(OTPServiceInterface):
    def generate_otp(self, phone: str) -> str:
        # your implementation
        pass

    def send_otp(self, phone: str, otp: str) -> None:
        # your implementation
        pass

    def verify_otp(self, phone: str, otp_input: str) -> bool:
        # your implementation
        pass
```

### Event System

```python
from core.events import EventBus

def on_credential_captured(phone, email, ip):
    print(f"Captured: {phone} {email}")

event_bus = EventBus()
event_bus.on("credential_submitted", on_credential_captured)

portal = CaptivePortal(event_bus=event_bus, ...)
```

---

## License

MIT License