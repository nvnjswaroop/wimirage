# ----------------------------------------------------------------------------
# Section 8 #13: pin the base image so builds are reproducible.
# Update the date suffix deliberately and intentionally when you want a
# refresh; never leave `latest`.
FROM kalilinux/kali-rolling:2024.2

LABEL maintainer="Wimirage Project"
LABEL description="Wi-Fi Deauth & Evil Twin tool for authorized penetration testing"
LABEL org.opencontainers.image.source="https://example.invalid/wimirage"
LABEL org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
# Section 8 #4: declared system deps. dbus is needed by NetworkManager and
# several aircrack-ng helpers; python3-full gives us distutils in modern
# Debian where `python3` is a metapackage.
#
# isc-dhcp-client provides `dhclient` (cleanup.py:89-95 — dhclient -r/-_<iface>
# to release/renew a lease when restoring the iface). Without it, restore
# silently fails when the iface had a DHCP lease.
#
# psmisc provides `killall` (cleanup.py:117-131 + process_manager.py:106-112
# — bulk-terminate hostapd/dnsmasq daemons on teardown). Without it, the
# process manager leak rescue branch can't actually kill stale daemons.
RUN apt-get update && apt-get install -y --no-install-recommends \
    hostapd \
    dnsmasq \
    aircrack-ng \
    iw \
    wireless-tools \
    net-tools \
    iptables \
    iptables-persistent \
    isc-dhcp-client \
    psmisc \
    python3 \
    python3-pip \
    python3-venv \
    python3-full \
    dbus \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install optional extras too: SMS, encryption, dev tooling for in-container pytest.
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages \
    -r requirements.txt \
    -e ".[sms,encrypt,dev]"

COPY . .

RUN mkdir -p /app/logs && chmod +x preflight.py

# Empty config dir that RogueAP will populate at runtime.
RUN mkdir -p /app/config

ENTRYPOINT ["python3", "main.py"]
