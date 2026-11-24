# Security Policy

## Supported Versions

Security fixes are applied to the latest release on the default branch (`master`). Older container tags and commits are not backported.

| Version | Supported |
| --- | --- |
| Latest (`master` / current release) | Yes |
| Earlier releases | No |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions.**

Instead, report vulnerabilities privately using one of the following channels:

1. **GitHub Security Advisories (Preferred):** Use the repository's **Security → Advisories → Report a vulnerability** button so the issue can be triaged, patched, and coordinated privately.
2. **Private Maintainer Contact:** If GitHub Security Advisories are unavailable, contact the repository maintainer privately via the email address listed in the repository's git metadata.

### What to Include
- A clear description of the vulnerability and its security impact.
- Affected component/file paths (e.g., `src/attestation.rs`, `src/rate_limit.rs`, `src/sync.rs`).
- Minimal reproduction steps or a proof-of-concept test case (e.g., a unit test or sample certificate chain).
- Any suggested remediation or mitigation.

> **Never attach real GCP/Firebase Service Account private keys, production App Check JWTs, or private APK signing keystores to a report.**

### Response Targets
- **Initial acknowledgment:** Within **72 hours**.
- **Triage & severity assessment:** Within **7 days**.
- **Remediation & coordinated disclosure:** Critical and high-severity issues (such as attestation verification bypasses) are prioritized for an immediate patch and advisory publication once a fix is available.

---

## Security Scope

### In Scope
- Cryptographic or X.509 certificate chain verification bypasses in `src/attestation.rs` or `src/roots.rs`.
- ASN.1 `KeyDescription` / `RootOfTrust` / `attestationApplicationId` parsing bugs or bypasses.
- Google CRL revocation bypasses or GrapheneOS `SSHSIG` / anti-rollback bypasses in `src/sync.rs`.
- Challenge replay or race conditions in `src/state.rs`.
- Rate-limiting bypasses, memory exhaustion (OOM DoS), or request smuggling issues in `src/rate_limit.rs` and `src/routes.rs`.
- Credential/secret leakage in logs, HTTP error responses, or container artifacts.

### Out of Scope (Inherent Architecture Boundaries)
The following are documented threat-model boundaries of hardware key attestation and Firebase App Check rather than bugs in `attest-gate` (see [DOCUMENTATION.md](DOCUMENTATION.md) for details):
- Replay of an already-minted 1-hour Firebase App Check bearer JWT stolen from a compromised device or intercepted over misconfigured non-TLS transport.
- Attestation forgery using a leaked OEM attestation keybox that has **not yet** been revoked in Google's `android.googleapis.com/attestation/status` feed (or within the normal 6-hour CRL refresh window).
- Relaying challenges to a farm of physical, bootloader-locked devices running the unmodified release APK.
- Automation or quota abuse from a genuine, locked device running the genuine APK (mitigate with Firebase Auth, server-side user quotas, and billing alerts).
- Misconfigurations by the deployer (such as exposing plain HTTP without TLS, setting `PROXY_IP_MODE=cloudflare` when origin is directly reachable, or allowlisting debug signing certificates in production).

---

## Operator Hardening Checklist

Before deploying `attest-gate` in production:
1. **Terminate TLS 1.2/1.3** at your ingress/reverse proxy; never expose port `8080` directly over plain HTTP.
2. **Use a dedicated, least-privilege GCP Service Account** solely for `attest-gate` (Google's App Check REST API uses the `cloud-platform` OAuth2 scope, so IAM roles are the permission boundary).
3. **Match `PROXY_IP_MODE` and `TRUSTED_PROXY_HOPS`** to your actual proxy topology (`direct` if exposed directly, `xff` behind Traefik/nginx, `cloudflare` **only** if origin blocks all non-Cloudflare IPs).
4. **Never add debug APK signing SHA-256 digests** to `ALLOWED_SIGNING_CERT_SHA256` in production.
5. **Pair App Check with per-user quotas and GCP billing alerts** when protecting metered backends like Firebase AI Logic / Gemini.
