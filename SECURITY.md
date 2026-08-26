# Security Policy

## ⚠️ Authorised-use only

`wimirage` is an offensive-security tool. It is published **so
that penetration testers, red teams, and security researchers can audit
Wi-Fi networks they own or have explicit written permission to test.**

Using this tool against networks you do not own or lack permission to
test is **illegal** in most jurisdictions under computer-misuse and
unauthorised-access statutes. The maintainers do not condone such use
and are not responsible for it.

If you are researching Wi-Fi vulnerabilities without explicit
authorisation, you do not need this tool — there are research networks
that legally emulate the conditions this tool targets.

---

## Supported versions

Only the latest minor of `wimirage` is supported with security
fixes. Older releases may continue to work but will not receive
patches.

| Version | Supported        |
|---------|------------------|
| 2.x     | ✅ Active        |
| 1.x     | ❌ End-of-life   |

---

## Reporting a vulnerability

We accept vulnerability reports for issues that affect users of the
tool itself (e.g. arbitrary code execution when the user runs our
**legitimate** binary, leaked credentials from the toolkit's own
secrets, CVEs in our pinned dependencies). We do **not** accept
reports about the tool being used to attack third parties — that is
not a vulnerability in the tool, that is misuse.

### What to report

- Authentication bypass or privilege escalation *within the
  toolkit itself* (e.g., the captive-portal admin endpoint, the
  JSONL credential log).
- Sensitive data exposure from our distribution (e.g., leaked
  signing keys, hard-coded API tokens in a release artifact).
- Code-execution via `pip install wimirage==<bad-version>`.
- Vulnerabilities in our default config templates (`config/*.j2`)
  that ship in releases.
- Vulnerable dependency transitively required via our `requirements.lock`.

### What does **not** count as a vulnerability report

- "The tool can be used to attack networks" — by design. Use authorised
  test infrastructure.
- "The default Twilio API key is visible to me in `/proc/<pid>/cmdline`"
  — this is the responsibility of the user to set environment
  variables; see Section 3 of `CHANGELOG.md`.
- Findings about specific Wi-Fi AP firmware / vendor
  implementations — please report those to the vendor directly.

### Where to send

Open a GitHub issue with the `security` label, **or** email the
maintainer at `security@<repo>.invalid` if you prefer private
disclosure. Expect an acknowledgement within **5 business days**.

For severe issues (RCE-without-user-action, secret leaks):
- Prefer private disclosure (email).
- Do not file a public issue.

---

## Disclosure timeline

We follow a 90-day coordinated disclosure model.

1. **Triage** (≤ 5 business days)
   - Acknowledge receipt.
   - Confirm or refute the bug.
2. **Patch** (≤ 30 days for critical; ≤ 90 days for the rest)
   - Develop a fix in a private branch.
   - Prepare a CVE request (we'll request one through MITRE unless you
     prefer to).
3. **Coordinated release**
   - We publish the fix and the advisory together.
   - You may publish your report at this point or hold for any reason
     you have.
4. **Post-mortem** (within a week of release)
   - Add an entry to the `## [Unreleased]` section of `CHANGELOG.md`
     describing the fix without leaking exploit details until users
     have had time to upgrade.

If we cannot reproduce the issue or believe it is out of scope, we'll
say so honestly and explain why.

---

## Hardening checklist for operators

If you're publishing wimirage into a test lab, the following is a
defence-in-depth checklist. None of these are defaults in our CLI
because we do not know your environment; configure them yourself.

- [ ] Run as a dedicated unprivileged user when not actively
      deauthing; only escalate with `sudo` for the duration of the
      attack window.
- [ ] Use Fernet-encrypted credential logs (`AppConfig.encrypted_logs
      = True; supply AppConfig.encryption_key`).
- [ ] Rotate `AppConfig.secret_key` per engagement.
- [ ] Optional but recommended: enable TLS for the captive portal
      (`CaptivePortal(ssl_context="adhoc")` or supply your own
      cert/key pair).
- [ ] Restrict outbound traffic to your Twilio region with
      `iptables -A OUTPUT -p tcp --dport 443 -d <twilio-ip-cidr> -j ACCEPT`.
- [ ] Cron-rotate `~/.../captured_credentials.jsonl` to off-host
      storage.

---

## Cryptography we use

| Function                | Algorithm | Where                                  |
|-------------------------|-----------|----------------------------------------|
| Password/secret hashing | N/A       | We do **not** store user passwords.    |
| OTP hashing             | SHA-256   | `core/otp_service.py:35`               |
| OTP timing-safe compare | HMAC-DRBG inside `hmac.compare_digest` | `core/otp_service.py:66` |
| Credential log at rest  | Fernet (AES-128-CBC + HMAC-SHA256) | `utils/logger.py:_encrypt_field` |
| Flask session signing   | itsdangerous (HMAC-SHA1) | Default Flask, see docs |

If you find any of these insufficient for your threat model, open an
issue and we'll evaluate the upgrade in our next release.

---

## Threat-model exclusions

The following are **not** part of the security model of this tool:

- Wi-Fi driver bugs.
- Local privilege escalation on the operator's host (we run as root
  intentionally; that's the assumption).
- Network capture from third parties (this is the tool's purpose).
- Long-term credential storage security beyond operator-defined key
  management.
- Resistance to physical access / evil-maid attacks against the
  operator's own host.

If you need those properties, you need a different tool.
