# Wi-Fi Deauth & Evil Twin — User Manual

---

## Table of Contents

1. [Overview](#overview)
2. [Legal Disclaimer](#legal-disclaimer)
3. [System Requirements](#system-requirements)
4. [Hardware Requirements](#hardware-requirements)
5. [Installation](#installation)
6. [Project Structure](#project-structure)
7. [How It Works](#how-it-works)
8. [Step-by-Step Usage](#step-by-step-usage)
9. [Menu Options Explained](#menu-options-explained)
10. [Captive Portal Flow](#captive-portal-flow)
11. [OTP Service Configuration](#otp-service-configuration)
12. [Running the Tests](#running-the-tests)
13. [Troubleshooting](#troubleshooting)
14. [Cleanup & Recovery](#cleanup--recovery)
15. [Log Files](#log-files)
16. [FAQ](#faq)

---

## Overview

This tool performs a Wi-Fi deauthentication and Evil Twin access point attack for **authorized penetration testing**. It works in two phases:

1. **Deauth Phase** — Sends spoofed 802.11 deauthentication frames to disconnect all clients (or a specific client) from a target access point.
2. **Evil Twin Phase** — Spins up a rogue AP that clones the target's SSID and channel. Disconnected clients auto-reconnect to the stronger rogue AP. A captive portal then harvests phone numbers and email IDs under the guise of "Wi-Fi verification."

Victims enter their phone number and email, receive an OTP for verification, and upon successful verification — are granted internet access (forwarded through the attacker's interface).

---

## Legal Disclaimer

```
THIS TOOL IS FOR AUTHORIZED PENETRATION TESTING ONLY.

Unauthorized use of this tool to attack networks you do not own
or have explicit written permission to test is ILLEGAL in most
jurisdictions. Violators may face criminal prosecution.

The developers assume no liability and are not responsible for
any misuse or damage caused by this tool. Use responsibly.
```

---

## System Requirements

| Component     | Requirement                          |
|---------------|--------------------------------------|
| OS            | Linux (Kali Linux recommended)       |
| Python        | 3.8 or higher                        |
| Privileges    | Root (sudo)                          |
| Kernel        | Supports monitor mode & packet injection |

---

## Hardware Requirements

| Item                                    | Details                                              |
|-----------------------------------------|------------------------------------------------------|
| Wi-Fi Adapter #1 (Deauth)              | Must support **monitor mode** + **packet injection** |
| Wi-Fi Adapter #2 (Rogue AP)            | Must support **AP mode** (master mode)               |
| Recommended Chipsets                    | RTL8812AU, Atheros AR9271, Ralink RT3070            |
| Recommended Adapters                    | Alfa AWUS036ACH, TP-Link WN722N (v1 only), Panda PAU09 |
| Internet Connection                     | Ethernet or second Wi-Fi adapter for upstream routing |

> **Note:** You need **two** Wi-Fi adapters. One handles deauth (monitor mode), the other hosts the rogue AP (AP mode). A single adapter cannot do both simultaneously.

---

## Installation

### 1. Install System Dependencies

```bash
sudo apt update
sudo apt install -y hostapd dnsmasq aircrack-ng iw wireless-tools
```

### 2. Install Python Dependencies

```bash
cd Wifi-project
pip install -r requirements.txt
```

For the optional extras (Twilio SMS, encrypted audit logs):

```bash
pip install -r requirements-dev.txt   # pytest, ruff
pip install twilio                    # real SMS OTP
```

**requirements.txt contents:**
```
scapy
flask
twilio
```

> `flask` ships Jinja2 transitively, so installing Flask alone gives you both.
> `twilio` is optional — only needed if you want real SMS OTP delivery.
> `cryptography` is optional — only needed for encrypted credential logs (`encrypted_logs=True`).

### 3. Verify Wireless Adapters

```bash
iwconfig
```

You should see at least two wireless interfaces (e.g., `wlan0`, `wlan1`).

### 4. Run the Tool

```bash
sudo python3 main.py
```

---

## Project Structure

```
Wifi-project/
├── main.py                     # CLI orchestrator (entry point)
├── preflight.py                # Pre-run environment checks (root, deps, adapter, etc.)
├── requirements.txt            # Runtime Python dependencies
├── requirements-dev.txt        # Test + lint dependencies (pytest, ruff)
├── pyproject.toml              # Project metadata + tool configuration
├── MANUAL.md                   # This manual
├── Dockerfile                  # Kali-based container build
├── .env.example                # Template for TWILIO_SID / TOKEN / phone / encryption key
├── core/
│   ├── __init__.py
│   ├── scanner.py              # AP scanning & enumeration (Scapy)
│   ├── deauth.py               # Deauthentication frame sender
│   ├── rogue_ap.py             # Rogue AP via hostapd + dnsmasq
│   ├── network.py              # iptables NAT, routing, IP forwarding
│   ├── captive_portal.py       # Flask web server (credential harvest)
│   ├── otp_service.py           # Demo & Twilio OTP services
│   ├── events.py               # In-process EventBus
│   ├── process_manager.py      # Supervises hostapd / dnsmasq / scanners
│   └── models.py               # Dataclasses (AppConfig, AccessPoint, …)
├── portal/
│   ├── templates/
│   │   ├── login.html          # Phone + email input page
│   │   ├── otp.html            # OTP verification page
│   │   └── success.html        # Post-authentication success page
│   └── static/
│       ├── style.css           # Dark glassmorphism UI
│       └── script.js           # OTP auto-focus, countdown, validation
├── config/                     # Auto-generated at runtime
│   ├── hostapd.conf            # Generated from target AP config
│   └── dnsmasq.conf            # Generated DHCP + DNS config
├── utils/
│   ├── __init__.py
│   ├── monitor_mode.py         # Monitor mode enable/disable
│   ├── logger.py               # Credential logging (JSON + terminal, batch flushed)
│   └── cleanup.py              # System restore on exit
├── tests/                      # pytest suite
│   ├── conftest.py             # Shared pytest fixtures
│   ├── test_scanner.py
│   ├── test_deauth.py
│   ├── test_network.py
│   ├── test_captive_portal.py
│   ├── test_otp_service.py
│   ├── test_state_machine.py   # State machine valid/invalid transitions
│   ├── test_process_manager.py # Watchdog & restart callback
│   ├── test_templates.py       # HTML/CSRF rendering checks
│   ├── test_integration.py     # Full attack chain (mocked)
│   ├── test_cleanup.py         # SIGINT handler coverage
│   ├── test_monitor_mode.py
│   ├── test_logger.py
│   ├── test_events.py
│   ├── test_models.py
│   └── test_script.mjs         # Node-based test for portal/static/script.js
├── docs/
│   └── architecture.mermaid    # System architecture (Mermaid.js)
├── CHANGELOG.md                # Version history
├── CONTRIBUTING.md             # Dev setup & PR template
└── logs/
    ├── captured_credentials.json  # Auto-created, stores harvested data
    └── audit.log                  # Tamper-evident rotating audit log
```

---

## How It Works

### Architecture

```
[Target AP]  <---deauth frames---  [Attacker: Monitor Adapter]
                                            |
                                   [Rogue AP: hostapd]
                                            |
                                   [DHCP: dnsmasq]  → 10.0.0.x
                                            |
                                   [iptables NAT/Routing]
                                            |
                                   [Captive Portal: Flask]  ← Victim connects here
                                            |
                                   [OTP Service: Demo/Twilio]
                                            |
                                   [Internet: Forwarded via eth0]
```

### Attack Flow

1. **Scan** — Discover nearby APs (SSID, BSSID, channel, signal, encryption, clients).
2. **Select Target** — Pick the AP you want to attack.
3. **Deauth** — Flood the target AP with deauth frames, disconnecting clients.
4. **Rogue AP** — Start a clone of the target on a second adapter with the same SSID and channel.
5. **Network Routing** — Configure iptables to redirect victim HTTP traffic to the captive portal.
6. **Captive Portal** — Victim sees a "Free Wi-Fi — Verify Your Identity" page asking for phone number and email.
7. **OTP Verification** — Victim enters the OTP (sent via demo mode or Twilio SMS).
8. **Credential Harvest** — Phone, email, and OTP are logged to terminal and JSON file.
9. **Internet Access** — After verification, iptables redirect is removed for that IP, granting real internet access via NAT.

---

## Step-by-Step Usage

### Quick Start (Full Attack Chain — Option 7)

This is the fastest way to run the complete attack:

```bash
sudo python3 main.py
```

1. Select **7** from the main menu.
2. Select your **monitor mode adapter** (for deauth).
3. Select your **AP mode adapter** (for rogue AP).
4. Enter your **internet-facing interface** (e.g., `eth0`).
5. The tool scans for APs — select your **target** from the list.
6. Choose an **OTP service**:
   - `d` = Demo (OTP printed to terminal — for testing)
   - `t` = Twilio (real SMS delivery — requires credentials)
   - `n` = None (skips OTP, auto-verifies)
7. The full chain starts automatically:
   - Deauth attack begins
   - Rogue AP launches
   - iptables rules are configured
   - Captive portal starts on port 80
8. Victims connect, submit credentials, and get verified.
9. Press **Ctrl+C** to stop — cleanup runs automatically.

### Manual Step-by-Step (Options 1–6)

Use individual menu options for more control:

| Step | Menu Option | Action                                          |
|------|-------------|-------------------------------------------------|
| 1    | Option 1    | Scan for APs                                    |
| 2    | Option 2    | Select target AP                                |
| 3    | Option 3    | Start deauth attack (broadcast or targeted)     |
| 4    | Option 4    | Launch Evil Twin (Rogue AP)                     |
| 5    | Option 5    | Start captive portal + configure network        |
| 6    | —           | Wait for victims in terminal                    |
| 7    | Option 8    | View captured credentials                       |
| 8    | Option 9/0  | Stop all / Exit with cleanup                    |

---

## Menu Options Explained

### Option 1 — Scan for Access Points

- Enables monitor mode on the selected adapter
- Scans for 20 seconds (configurable in code)
- Displays all discovered APs with:
  - SSID, BSSID, Channel, Signal (dBm), Encryption, Connected clients count
- Stores results in memory for target selection

### Option 2 — Select Target AP

- Shows the scanned AP list
- Enter the number next to the target AP
- Stores the selected AP's BSSID, SSID, channel for deauth and rogue AP

### Option 3 — Start Deauth Attack

- Two modes:
  - **Broadcast** — Disconnects ALL clients from the target AP
  - **Targeted** — Disconnects a specific client (by MAC address)
- Configurable packets-per-second (default: 100 PPS)
- Runs continuously until stopped
- The deauth module auto-locks to the target AP's channel

### Option 4 — Launch Evil Twin

- Generates `hostapd.conf` cloning the target SSID and channel
- Generates `dnsmasq.conf` with DHCP range 10.0.0.2–10.0.0.100
- Starts `hostapd` and `dnsmasq` on the AP adapter
- Configures the adapter IP as 10.0.0.1

### Option 5 — Start Captive Portal

- Asks for the internet-facing interface (e.g., `eth0`)
- Configures iptables NAT, DNS redirect, and HTTP redirect to portal
- Starts Flask web server on port 80
- Select OTP service:
  - **Demo** — OTP is printed to the attacker's terminal (for testing)
  - **Twilio** — Real SMS OTP sent to the victim's phone number
  - **None** — No OTP, auto-verifies all submissions

### Option 6 — Configure Network Routing

- Sets up iptables without starting the portal (useful if portal is already running)
- Configures:
  - HTTP DNAT redirect to captive portal
  - DNS redirect to local dnsmasq
  - NAT masquerade on internet interface
  - IP forwarding

### Option 7 — Run Full Attack Chain

- Runs all steps 1–6 automatically in sequence
- One-shot complete attack
- Ctrl+C stops everything and runs cleanup

### Option 8 — View Captured Credentials

- Displays all harvested credentials in a formatted table
- Shows summary statistics (total entries, verified victims, unique phones/emails)

### Option 9 — Stop All

- Stops deauth attack
- Stops rogue AP (kills hostapd + dnsmasq)
- Flushes iptables rules
- Disables IP forwarding
- Does NOT restore interfaces (use Exit for full cleanup)

### Option 0 — Exit

- Stops all active attacks
- Runs full cleanup:
  - Kills hostapd, dnsmasq
  - Flushes all iptables rules
  - Disables IP forwarding
  - Restores wireless adapters to managed mode
  - Restarts NetworkManager
- Exits the program

---

## Captive Portal Flow

### What the Victim Sees

#### Page 1 — Login (`login.html`)
```
┌─────────────────────────────────┐
│         [Wi-Fi Icon]            │
│        Free Wi-Fi               │
│  Verify your identity to connect│
│                                 │
│  Phone Number:                  │
│  [+91 ▼] [____________]        │
│                                 │
│  Email Address:                 │
│  [__________________________]   │
│                                 │
│      [ Send OTP ]              │
│                                 │
│  By connecting, you agree...    │
└─────────────────────────────────┘
```

- Phone number with country code selector (supports 10 countries)
- Email address with validation
- "Send OTP" button triggers OTP generation + delivery

#### Page 2 — OTP Verification (`otp.html`)
```
┌─────────────────────────────────┐
│         [Wi-Fi Icon]            │
│         Verify OTP              │
│  Enter code sent to +91XXXX     │
│                                 │
│  [ ] [ ] [ ] [ ] [ ] [ ]       │
│                                 │
│    [ Verify & Connect ]        │
│                                 │
│  Didn't receive? Resend OTP    │
│  OTP expires in 4:32           │
└─────────────────────────────────┘
```

- 6 individual digit input boxes (auto-advance focus)
- Paste support (paste full OTP and it fills all boxes)
- Auto-submits when all 6 digits are entered
- 5-minute countdown timer
- Resend OTP button (30-second cooldown)

#### Page 3 — Success (`success.html`)
```
┌─────────────────────────────────┐
│         [✓ Icon]                │
│        Connected!               │
│  Authentication successful.    │
│  ████████████████████░░░       │
│  Redirecting you shortly...     │
└─────────────────────────────────┘
```

- Success confirmation with animated loading bar
- Auto-redirects to google.com after 3 seconds
- iptables redirect is removed for this client → full internet access

---

## OTP Service Configuration

### Demo Mode (Default)

- OTP is generated and **printed to the attacker's terminal**
- No SMS is actually sent
- Use this for testing the portal flow
- Any 6-digit code shown in the terminal works

**Terminal output:**
```
[*] DEMO OTP for +919876543210: 482916
```

### Twilio Mode (Real SMS)

To send real OTPs via SMS:

1. Create a [Twilio account](https://www.twilio.com/) (free trial available)
2. Get your Account SID, Auth Token, and a phone number
3. When prompted, select `t` for Twilio and enter:
   - Account SID
   - Auth Token
   - Twilio phone number (e.g., +1234567890)

**Note:** Twilio trial accounts can only send to verified numbers. Upgrade for production use.

### Custom OTP Service

To implement your own OTP service, create a class that inherits from `OTPServiceInterface`:

```python
from core.otp_service import OTPServiceInterface

class MyOTPService(OTPServiceInterface):
    def generate_otp(self, phone):
        # Generate and store OTP
        pass

    def send_otp(self, phone, otp):
        # Send OTP via your preferred method
        pass

    def verify_otp(self, phone, otp_input):
        # Verify the user's input against stored OTP
        pass
```

Then pass it to the `CaptivePortal`:

```python
portal = CaptivePortal(otp_service=MyOTPService())
```

---

## Running the Tests

The project ships with a pytest suite covering every module plus a self-contained Node test for the front-end `script.js`. None of the tests touch real hardware — subprocesses and network calls are mocked.

### Install test dependencies

```bash
pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes `pytest`, `pytest-cov`, `ruff`, and `mutmut`.

### Run the full Python suite

```bash
pytest                       # run all tests
pytest -v                    # verbose, one line per test
pytest tests/test_state_machine.py   # single file
pytest -k "process"          # filter by name
```

Coverage report:

```bash
pytest --cov=core --cov=utils --cov=main --cov-report=term-missing
```

### Run the front-end test (Node)

The OTP auto-advance / paste / countdown logic in `portal/static/script.js` is tested with a sandboxed DOM via Node's `vm` module. No `npm install` needed.

```bash
node tests/test_script.mjs
```

Expected output:

```
  ok   OTP focus is on box 0 after DOMContentLoaded
  ok   boxes have input+keydown+paste listeners attached
  ok   Hidden OTP input reflects concatenated box values
  ok   Filling all boxes submits the form
  ok   Backspace on empty box focuses previous
  ok   Paste of 6 digits distributes across boxes and submits
  ok   Resend button disables on click

tests/test_script.mjs: 7 passed, 0 failed
exit=0
```

### Lint

```bash
ruff check core/ utils/ main.py tests/
```

### Mutation testing (optional)

```bash
mutmut run --paths-to-mutate=core,utils
mutmut results
```

> Tests must be run on a Linux box with the system packages from the [Installation](#installation) section. The suite is fully hermetic; it does NOT need root or a wireless adapter.

---

## Troubleshooting

### "This tool must be run as root"
- Run with `sudo`: `sudo python3 main.py`

### "No wireless interfaces found"
- Check adapters: `iwconfig`
- Ensure drivers are loaded: `lsmod | grep 80211`
- Try `ip link show` to see all interfaces

### "hostapd failed to start"
- Ensure the adapter supports AP mode: `iw list | grep "AP"`
- Kill conflicting processes: `sudo airmon-ng check kill`
- Check if another process is using the interface: `sudo lsof | grep wlan`

### "dnsmasq failed to start"
- Kill existing dnsmasq: `sudo killall dnsmasq`
- Check if systemd-resolved is using port 53: `sudo systemctl stop systemd-resolved`

### Monitor mode won't enable
- Try airmon-ng: `sudo airmon-ng start wlan0`
- Check for interfering processes: `sudo airmon-ng check`
- Some adapters need specific drivers — check chipset compatibility

### No clients connecting to Evil Twin
- Ensure deauth is running continuously
- Check that the rogue AP is on the **same channel** as the target
- Try moving closer to the victims (stronger signal wins)
- Verify the rogue AP adapter supports AP mode

### Captive portal not loading
- Ensure iptables rules are set (Option 5 or 6)
- Check dnsmasq is running: `ps aux | grep dnsmasq`
- Verify the Flask server is on port 80: `ss -tlnp | grep :80`
- Ensure IP forwarding is enabled: `cat /proc/sys/net/ipv4/ip_forward`

### OTP not sending (Twilio)
- Verify Twilio credentials are correct
- Trial accounts only send to verified numbers
- Check Twilio console for error logs
- Ensure `twilio` package is installed: `pip install twilio`

---

## Cleanup & Recovery

### Automatic Cleanup

The tool handles cleanup automatically on:
- **Ctrl+C** — Signal handler triggers full cleanup
- **Option 0 (Exit)** — Full cleanup before exit
- **Option 9 (Stop All)** — Partial cleanup (stops attacks, flushes iptables)

### What Cleanup Does

1. Kills `hostapd` and `dnsmasq` processes
2. Flushes all iptables rules (nat, filter)
3. Disables IP forwarding
4. Restores wireless adapters from monitor mode to managed mode
5. Restarts NetworkManager
6. Runs `dhclient` to restore DHCP on interfaces

### Manual Cleanup

If the tool crashes or cleanup fails:

```bash
# Kill processes
sudo killall hostapd dnsmasq 2>/dev/null

# Flush iptables
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -X
sudo iptables -t nat -X

# Disable IP forwarding
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward

# Restore interfaces
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode managed
sudo ip link set wlan0 up

# Restart NetworkManager
sudo systemctl restart NetworkManager
sudo dhclient wlan0
```

---

## Log Files

All captured credentials are stored in:

```
Wifi-project/logs/captured_credentials.json
```

### Log Format

```json
[
  {
    "timestamp": "2026-06-17 14:30:22",
    "client_ip": "10.0.0.15",
    "phone": "+919876543210",
    "email": "victim@example.com",
    "otp": "482916",
    "stage": "otp_verified"
  }
]
```

### Stages

| Stage                  | Meaning                                      |
|------------------------|----------------------------------------------|
| `phone_email_submitted`| Victim submitted phone + email on login page |
| `otp_verified`         | Victim entered correct OTP                   |
| `otp_failed`           | Victim entered incorrect OTP                 |

### Viewing Logs

From the main menu, select **Option 8** or read the JSON file:

```bash
cat logs/captured_credentials.json | python3 -m json.tool
```

---

## FAQ

**Q: Can I use a single Wi-Fi adapter?**  
A: No. You need two adapters — one for deauth (monitor mode) and one for the rogue AP (AP mode). A single adapter cannot operate in both modes simultaneously.

**Q: Does this work on Windows or macOS?**  
A: No. Linux is required for monitor mode, packet injection, hostapd, dnsmasq, and iptables. Kali Linux is recommended.

**Q: Can I deauth a specific client instead of all?**  
A: Yes. When starting the deauth attack (Option 3), select "Targeted" mode and choose a client from the list.

**Q: What if the target AP is on 5GHz?**  
A: Your adapter must support 5GHz (dual-band). Set `hw_mode=a` in hostapd config for 5GHz.

**Q: How do I make the Evil Twin stronger than the real AP?**  
A: Physical proximity matters most. You can also increase TX power: `sudo iwconfig wlan1 txpower 30` (where legal).

**Q: Will victims see two APs with the same name?**  
A: Most devices show only one. They auto-connect to the stronger signal. Your rogue AP should have a stronger signal if you're closer.

**Q: What happens after a victim verifies OTP?**  
A: Their IP is removed from the iptables redirect rule, so all their traffic is NAT'd through your internet interface — they get real internet access.

**Q: Is HTTPS traffic captured?**  
A: No. Only HTTP traffic is redirected to the portal. HTTPS sites would show certificate warnings. The captive portal only handles the initial verification over HTTP.

**Q: Can I customize the portal pages?**  
A: Yes. Edit the HTML files in `portal/templates/`. You can brand them to mimic any Wi-Fi provider. The CSS supports mobile-responsive design.

**Q: How do I add more country codes?**  
A: Edit the `<select>` in `portal/templates/login.html` and add more `<option>` tags.
