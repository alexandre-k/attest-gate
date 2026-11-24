# `attest-gate` Documentation

## 1. Overview

`attest-gate` is a self-hosted Rust microservice that bridges **Android Hardware Key Attestation** with **Firebase App Check** without relying on Google Play Services or the Google Play Integrity API.

Its primary goal is to protect Firebase-backed resources—such as **Firebase AI Logic (Gemini / Vertex AI in Firebase)**—so that requests come from an unmodified release build of your Android app running on a genuine, bootloader-locked physical Android device, while explicitly supporting **GrapheneOS** alongside stock OEM Android.

### High-Level Architecture & Request Flow

```text
Mobile App (Stock Android or GrapheneOS, no Play Services)
  │
  │ 1. POST /v1/challenge
  ├───────────────────────────────────────────► attest-gate (Rust / Axum)
  │◄──────────── 32-byte base64url nonce ──────┤   • ChallengeStore (DashMap, 60s TTL, single-use)
  │                                            │   • Google CRL sync (every 6h)
  │ 2. Generate ephemeral EC P-256 key in      │   • GrapheneOS SSHSIG key sync (every 6h)
  │    AndroidKeyStore (StrongBox -> TEE)      │   • Per-IP token-bucket rate limiter
  │    with attestationChallenge = nonce       │
  │    Read cert chain, then delete key        │
  │                                            │
  │ 3. POST /v1/attest (nonce + DER chain)     │
  ├───────────────────────────────────────────►│ 4. Verify attestation pipeline:
  │                                            │    - Atomic nonce consumption
  │                                            │    - X.509 chain & pinned Google root SPKI
  │                                            │    - Google CRL check (REVOKED / SUSPENDED)
  │                                            │    - OID 1.3.6.1.4.1.11129.2.1.17 KeyDescription
  │                                            │    - Hardware TEE/StrongBox security level
  │                                            │    - teeEnforced RootOfTrust (locked + verified/GrapheneOS)
  │                                            │    - attestationApplicationId (package + APK SHA-256)
  │                                            │
  │                                            │ 5. Sign RS256 Custom App Check JWT & exchange
  │                                            ├────────────► Firebase App Check REST API
  │◄──────── Official Firebase App Check JWT ──┤◄──────────── (:exchangeCustomToken)
  │
  │ 6. Call Firebase AI Logic / protected APIs with X-Firebase-AppCheck header
  └──────────────────────────────────────────────────────────────────────────► Firebase Backend
```

### Core Modules

| Module | Responsibility |
| --- | --- |
| `src/main.rs` | Loads env config, initializes JSON structured logging, runs initial trust-anchor sync, starts background eviction/sync tasks, and serves Axum HTTP with graceful shutdown (`SIGINT`/`SIGTERM`). |
| `src/config.rs` | Parses environment variables and loads the GCP/Firebase Service Account JSON from `GOOGLE_APPLICATION_CREDENTIALS`. |
| `src/roots.rs` | Embeds and self-verifies two pinned Google Android Hardware Attestation Root CA public keys (`SubjectPublicKeyInfo`). |
| `src/sync.rs` | Periodically (every 6h) fetches Google's attestation revocation list (`android.googleapis.com/attestation/status`) and GrapheneOS's OpenSSH-signed verified boot keys (`grapheneos.org/attestation.json` + `.sig`). |
| `src/state.rs` | Holds the in-memory `ChallengeStore` (`DashMap`), `TrustAnchors` (`RwLock`), and shared `AppState`. |
| `src/attestation.rs` | Implements the X.509 chain, CRL, and ASN.1 DER `KeyDescription` verification pipeline. |
| `src/firebase.rs` | Exchanges Service Account RS256 assertions for a cached (50m) Google OAuth2 bearer token and mints official Firebase App Check tokens (`3600s` TTL) via `:exchangeCustomToken`. |
| `src/rate_limit.rs` | Per-IP token-bucket rate-limiting middleware backed by `DashMap`. |
| `src/routes.rs` | Axum HTTP router (`GET /livez`, `GET /healthz`, `POST /v1/challenge`, `POST /v1/attest`), 64 KiB body limit, and request tracing. |
| `src/error.rs` | Maps internal error variants to JSON HTTP responses (`400`, `403`, `429`, `500`, `502`, `503`). |

---

## 2. HTTP API & Configuration

### Endpoints

1. **`GET /livez`**
   - Exempt from rate limiting.
   - Lightweight liveness probe returning `200 OK` (`{"status": "ok"}`) while the HTTP runtime is responsive.

2. **`GET /healthz`**
   - Exempt from rate limiting.
   - Readiness probe returning `200 OK` when trust anchors are synced and fresh, or **`503 Service Unavailable`** when the Google CRL is unsynced/stale (>48h) or GrapheneOS keys are required and unsynced.
   - Intentionally omits internal error strings and live challenge counts from the public JSON response.

3. **`POST /v1/challenge`**
   - Issues a fresh 32-byte cryptographically random nonce encoded as base64url (no padding) with a 60-second TTL.
   - Bounded to 10,000 active challenges in memory (returns `503 Service Unavailable` if at capacity after evicting expired entries).
   - Response: `{"challenge": "<43-char base64url>", "expires_in": 60}`.

4. **`POST /v1/attest`**
   - Request body (max 64 KiB):
     ```json
     {
       "challenge": "<base64url nonce from /v1/challenge>",
       "certificate_chain": ["<base64 DER leaf>", "<base64 DER intermediate>", "...", "<base64 DER root>"]
     }
     ```
   - On success (`200 OK`):
     ```json
     {
       "token": "<official Firebase App Check JWT>",
       "expire_time_millis": 1700003600000
     }
     ```

### Environment Variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GOOGLE_APPLICATION_CREDENTIALS` | Yes | — | Path to GCP/Firebase Service Account JSON. |
| `FIREBASE_PROJECT_NUMBER` | Yes | — | Numeric GCP/Firebase project number. |
| `FIREBASE_APP_ID` | Yes | — | Full Firebase Android App ID (`1:<num>:android:<hex>`). |
| `ALLOWED_PACKAGE_NAME` | Yes | — | Exact Android application ID allowed to attest. |
| `ALLOWED_SIGNING_CERT_SHA256` | Yes | — | Comma-separated SHA-256 hex fingerprints of allowed release APK signing certificates (colons/uppercase normalized). |
| `ALLOW_GRAPHENEOS` | No | `true` | Whether `SelfSigned` verified boot is permitted when the verified boot key matches GrapheneOS's signed feed. |
| `BIND_ADDR` | No | `0.0.0.0:8080` | TCP bind address (plain HTTP; TLS must be terminated upstream). |
| `RATE_LIMIT_RPM` | No | `60` | Sustained per-IP requests per minute. |
| `RATE_LIMIT_BURST` | No | `20` | Per-IP token-bucket burst size. |
| `PROXY_IP_MODE` | No | `direct` | Client IP extraction strategy: `direct` (TCP peer IP), `xff` (rightmost untrusted `X-Forwarded-For`), or `cloudflare` (`CF-Connecting-IP`; only safe when origin blocks non-Cloudflare traffic). |
| `TRUSTED_PROXY_HOPS` | No | `1` | Number of trusted reverse proxies appending to `X-Forwarded-For` when `PROXY_IP_MODE=xff`. |
| `TRUST_PROXY_HEADERS` | No | `false` | Legacy fallback boolean (`true` maps to `PROXY_IP_MODE=xff` when `PROXY_IP_MODE` is unset). |
| `FIREBASE_API_BASE` | No | `https://firebaseappcheck.googleapis.com` | Override for testing. |

---

## 3. What IS Secure

When deployed behind HTTPS with a dedicated least-privilege Service Account, `attest-gate` provides strong cryptographic and operational guarantees:

### Cryptographic & Attestation Guarantees
- **Hardware-Backed Root of Trust:** Enforces both `attestationSecurityLevel >= 1` and `keymasterSecurityLevel >= 1` (`TrustedEnvironment` or `StrongBox`), explicitly rejecting software-emulated attestations and software-backed keys (`Software = 0`).
- **Strict X.509 CA Chain Validation:** Enforces RFC 5280 certificate roles across the entire chain—every issuer (`certs[1..]`) must explicitly carry `BasicConstraints` with `cA=TRUE`, satisfy `pathLenConstraint`, and carry `KeyUsage` with `keyCertSign`; the leaf (`certs[0]`) is rejected if it claims `CA=TRUE` or `keyCertSign`. This prevents an end-entity Android Keystore certificate from being abused as a fake intermediate CA.
- **Pinned Google Hardware Root SPKIs:** Root trust is anchored by exact `SubjectPublicKeyInfo` byte matching against Google's embedded RSA-4096 and ECDSA P-384 (`Key Attestation CA1`) hardware roots (`src/roots.rs`), not the system CA store.
- **Fail-Closed & Freshness-Enforced Trust Anchors:** Attestation requests fail with `503 Service Unavailable` if Google's CRL has never completed an initial sync or is older than 48 hours (`MAX_CRL_AGE_SECS`), and likewise for GrapheneOS `SelfSigned` requests if the GrapheneOS feed has not synced. Failed syncs retry automatically with exponential backoff (10s up to 15m).
- **Revocation Enforcement:** Every certificate in the submitted chain (leaf, intermediates, and root) is checked against Google's `REVOKED` and `SUSPENDED` serial list, catching known leaked OEM attestation keyboxes.
- **Single-Use Challenge & Replay Prevention:** Challenges are 256-bit random nonces (`32` bytes), expire after 60 seconds, and are **atomically removed** from `ChallengeStore` on the first attestation attempt (even if verification fails). Nonce comparison inside `KeyDescription` uses constant-time byte equality.
- **Strict `teeEnforced` `RootOfTrust`:** `RootOfTrust` (`[704]`) is read *exclusively* from `teeEnforced` (never `softwareEnforced`). Unlocked bootloaders (`deviceLocked == false`), empty/all-zero `verifiedBootKey` values, and `Unverified` / `Failed` boot states are rejected.
- **Cryptographically Verified GrapheneOS Support:** GrapheneOS verified boot keys are never trusted from TLS alone—`attestation.json` is verified against a pinned OpenSSH Ed25519 key (`contact@grapheneos.org`) under the exact `"attestation keys"` namespace (double-checked via `ssh-key` and `ed25519-dalek`), with monotonic `timestamp` anti-rollback protection seeded by a compile-time minimum timestamp floor (`MIN_GRAPHENEOS_TIMESTAMP`).
- **App Identity Binding:** Verifies both `packageName` and release APK signing certificate SHA-256 inside `attestationApplicationId` (`[709]`), preventing repackaged/tampered APKs or unrelated apps from minting tokens.
- **Legacy Factory Root Compatibility Without Weakening Intermediates:** Per Google's verifier guidance, expired `notAfter` is tolerated *only* on the pinned root anchor (covering factory-provisioned 2016–2026 RSA-4096 roots that share the re-issued root SPKI), while intermediate and leaf validity periods and CRL checks remain enforced.

### Runtime, DoS & Container Hardening
- **Memory-Safe Implementation & Bounded I/O:** Written in Rust using `rustls` (no OpenSSL dependency), strict `64 KiB` HTTP request body limits, bounded upstream sync response reads (`10 MiB` CRL, `512 KiB` GrapheneOS JSON, `16 KiB` sig), and hard in-memory capacity caps (`10,000` active challenges, `50,000` IP rate-limit buckets) to prevent OOM DoS.
- **Spoofing-Resistant Rate Limiting:** Defaults to `PROXY_IP_MODE=direct` (direct TCP peer IP). When explicitly configured as `xff`, reads the **rightmost** untrusted hop in `X-Forwarded-For` rather than the client-spoofable leftmost value; `CF-Connecting-IP` is only trusted when `PROXY_IP_MODE=cloudflare` is explicitly chosen. Fails closed into a shared fallback bucket if no client IP can be resolved.
- **Minimal Public Surface:** No wildcard CORS headers; `403 Forbidden` responses return a generic `"Attestation verification failed"` message while logging detailed diagnostics server-side; `/healthz` returns `503` when degraded and omits internal error strings and challenge counters; `ServiceAccountCredentials` redacts `private_key` in `Debug` output.
- **Minimal Distroless Runtime & Hardened Pod Spec:** Built with `--locked` into `gcr.io/distroless/cc-debian12:nonroot` (UID `65532`), running non-root with `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, all Linux capabilities dropped (`ALL`), `seccompProfile: RuntimeDefault`, `automountServiceAccountToken: false`, and service account secret mounted read-only (`0400`).

---

## 4. What Is NOT Secure

Even with strict cryptographic and runtime hardening, **operational deployment choices** and **fundamental limits of hardware attestation + App Check** still define important security boundaries.

### A. Deployment-Dependent Security Assumptions
1. **Broad GCP OAuth2 Scope (`src/firebase.rs`):** Firebase App Check's REST API requires the `https://www.googleapis.com/auth/cloud-platform` OAuth2 scope, so the cached bearer token inherits *all* IAM permissions granted to the Service Account. You **must** dedicate a Service Account solely to `attest-gate` with strict least-privilege IAM roles.
2. **Proxy Header Trust Configuration (`PROXY_IP_MODE`):** Setting `PROXY_IP_MODE=cloudflare` when traffic can bypass Cloudflare and hit your origin ingress directly allows attackers to spoof `CF-Connecting-IP` and bypass rate limiting. Similarly, setting `TRUSTED_PROXY_HOPS` higher than your actual proxy chain allows leftmost `X-Forwarded-For` spoofing. Always match `PROXY_IP_MODE` and `TRUSTED_PROXY_HOPS` to your real network topology.
3. **Transport Security Outside the Service:** `attest-gate` listens on plain HTTP (`0.0.0.0:8080`). End-to-end security depends entirely on terminating TLS 1.2/1.3 at your ingress/load balancer and ensuring your Android release build does not trust user-installed CA certificates.

### B. Inherent Threat-Model Boundaries (What This Architecture Cannot Prevent)

1. **Bearer Token Theft & Replay (Up to 1 Hour):**
   - Firebase App Check tokens are stateless bearer JWTs valid for `3600s` (1 hour) and are **not** cryptographically bound to the device's hardware key (no DPoP/mTLS proof-of-possession).
   - If an attacker intercepts the token in transit (e.g., missing TLS or an Android app that trusts user-installed MITM CAs) or extracts it from a compromised device, they can replay that JWT from any script or server until it expires.
2. **Leaked OEM Keyboxes (Zero-Day / CRL Lag):**
   - Root/spoofing tools (e.g., TrickyStore) can forge hardware attestations using leaked OEM attestation keyboxes until Google adds those certificate serials to `android.googleapis.com/attestation/status`.
   - Because `attest-gate` syncs the CRL every 6 hours, there is an additional exposure window between Google revoking a keybox and `attest-gate` refreshing.
3. **Physical Device Farms & Challenge Relaying:**
   - An attacker with real locked Android devices running your genuine APK can relay server challenges from a remote bot to the physical devices and collect valid App Check tokens. Hardware attestation dramatically raises the cost of abuse compared to pure scripts, but does not make relaying impossible.
4. **Legitimate-Device Automation & Cost Abuse (LLM Quota Drain):**
   - A genuine, locked phone running your unmodified release APK can still be automated via Accessibility Services, ADB (`uiautomator`), or physical automation to spam Gemini/Firebase AI Logic calls.
   - **App Check verifies app/device integrity, not human intent or fair billing.** Always pair it with server-side per-user quotas, Firebase Auth, and GCP billing budgets/alerts.
5. **Unpatched or Compromised Stock OS Runtime:**
   - `attestationApplicationId` (`[709]`) is populated by Android's `keystore2` daemon (`softwareEnforced`) and signed by the TEE. Its trustworthiness assumes the verified OS image has not been compromised after boot. Because `attest-gate` does not currently enforce minimum `osVersion` or security patch levels, old locked devices with known local privilege escalation exploits remain accepted.
6. **Not User Authentication:**
   - App Check does not identify a user. It should complement—never replace—Firebase Auth / backend authorization.

---

## 5. What to Expect in Practice

### Latency & Performance
- **`POST /v1/challenge`:** Sub-millisecond (in-memory random generation + `DashMap` insert).
- **`POST /v1/attest`:** Typically **150–500 ms** end-to-end on the client:
  - Client-side StrongBox EC P-256 key generation + attestation can take ~50–300 ms depending on SoC (TEE is faster).
  - Server-side X.509/ASN.1 verification takes a few milliseconds.
  - Upstream call to Firebase `:exchangeCustomToken` adds ~100–250 ms (OAuth2 bearer token is cached for 50 minutes, avoiding an extra round-trip on most requests).
- **Frequency:** Because minted App Check tokens live for **1 hour** (`3600s`) and the Firebase App Check SDK caches and refreshes them proactively, each active device typically calls `attest-gate` only **once per hour** (or on cold app start if the cached token expired).
- **Footprint:** Very low CPU and RAM usage under normal load (tens of megabytes RSS), suitable for small `k3s` clusters.

### Device & Platform Compatibility Matrix

| Client Environment | Supported? | Notes |
| --- | --- | --- |
| Stock Android (Android 8.0+ with hardware Keymaster 3+ / KeyMint & locked bootloader) | **Yes** | `VerifiedBootState::Verified` + Google hardware root. |
| GrapheneOS (official releases, locked bootloader) | **Yes** (when `ALLOW_GRAPHENEOS=true`) | `VerifiedBootState::SelfSigned` verified against GrapheneOS's signed key list. |
| Other custom ROMs (LineageOS, CalyxOS, `/e/OS`, self-built AOSP) | **No** | `SelfSigned` key is not in GrapheneOS's feed; rejected. |
| Unlocked bootloader / rooted devices (Magisk, KernelSU, etc.) | **No** | Rejected (`deviceLocked == false` or `Unverified`/`Failed`), barring unrevoked leaked keyboxes. |
| Android Emulators / Debug builds | **No** | Emulators produce `Software (0)` attestations; debug builds fail `ALLOWED_SIGNING_CERT_SHA256` unless a debug digest is explicitly allowlisted (never do this in production). |
| Very old Android (< 8.0) or non-Google-provisioned hardware (e.g., Huawei HMS) | **No** | No hardware attestation chain rooted in Google's pinned roots. |
| Devices using unpinned Google hardware roots | **No** | Only 2 roots are currently embedded (`RSA-4096` and `ECDSA P-384 Key Attestation CA1`). Older factory ECDSA roots or future Google root rotations will fail until added to `src/roots.rs`. |
| iOS / Web | **No** | Android Key Attestation only; no Apple App Attest or Web provider. |

### Operational Behavior
- **Cold Start:** On boot, `attest-gate` fetches Google's CRL and GrapheneOS's keys *before* binding its HTTP port. Under healthy internet connectivity this takes ~1–2 seconds.
- **Rolling Restarts / Pod Rescheduling:** Because challenges live only in memory, any in-flight challenge issued right before a pod restart will fail with `403` and the client should retry from `/v1/challenge`.
- **Single-Replica Requirement:** The current in-memory `ChallengeStore` requires `replicas: 1` (or sticky routing by client, which is still fragile across pod churn).

---

## 6. Potential Shortcomings & Operational Risks

1. **Single Point of Failure (`replicas: 1`):** Running a single replica means pod restarts, node drains, or OOM events cause brief attestation outages (though already-minted 1-hour App Check tokens continue working on clients during short outages).
2. **48-Hour Fail-Closed Ceiling on Extended Upstream Outages:** If Google's CRL endpoint is unreachable for more than 48 consecutive hours, `attest-gate` intentionally fails closed (`503`) to avoid accepting revoked keyboxes indefinitely.
3. **Single App per Deployment:** `FIREBASE_APP_ID`, `ALLOWED_PACKAGE_NAME`, and `ALLOWED_SIGNING_CERT_SHA256` support only one Android app per `attest-gate` instance.
4. **No OS Security Patch / Version Floor or App Version Floor:** `osVersion`, `osPatchLevel`, `bootPatchLevel`, `vendorPatchLevel`, `origin`, and APK `versionCode` are not validated, so outdated/vulnerable OS images and older APK versions signed with the same release key remain accepted indefinitely.
5. **No Per-Device Rate Limiting or Anomaly Detection:** Rate limiting is IP-only. Users behind shared carrier-grade NAT (CGNAT) share one IP bucket (risking false-positive `429`s), while attackers rotating IPs or relaying via farms are not throttled per attestation key/device.
6. **Missing Client Reference Implementations:** `clients/android-kotlin/` and `clients/flutter/` currently contain only dependency snippets, not complete drop-in provider source files.
7. **Limited Observability:** Structured JSON logs are emitted, but there are no Prometheus/OpenTelemetry metrics (e.g., rejection breakdown by reason, CRL age, Firebase exchange latency).

---

## 7. What Could Come Next (Roadmap)

### Phase 1 — Reliability & Horizontal Scaling
- **Stateless Challenges or Shared Store:** Replace the in-memory `DashMap` with either:
  - **Redis / Valkey** (with atomic `GETDEL`) for true multi-replica HA and shared rate limiting, **or**
  - **HMAC-signed short-lived challenges** + a small shared/local spent-nonce cache for near-stateless scaling.
- **Persistent GrapheneOS Timestamp Floor:** Persist the latest accepted GrapheneOS `timestamp` to durable storage (in addition to the compile-time floor) to tighten rollback protection across restarts.
- **Metrics & Alerting:** Expose `/metrics` (Prometheus) on an internal port tracking attestation pass/fail counts by reason, upstream Firebase latency, CRL age, and active challenges.

### Phase 2 — Stronger Attestation Policy & Abuse Controls
- **Deeper KeyDescription Enforcement:**
  - Verify `origin == GENERATED` (`[702]`) in `teeEnforced`.
  - Optional configurable minimums for `osVersion`, `osPatchLevel`, `bootPatchLevel`, `vendorPatchLevel`, and APK `versionCode`.
- **Additional Google Roots & Root Lifecycle Tracking:** Audit and embed any additional active Google hardware attestation roots (e.g., legacy factory ECDSA P-384 roots if targeting affected devices) and add automated monitoring for Google's root rotation announcements.
- **Reduced Token TTL / Adaptive Risk:** Make `APP_CHECK_TOKEN_TTL` configurable (e.g., shorter TTL for higher-sensitivity endpoints) and consider tracking anonymized device/intermediate-cert velocity to detect attestation farms.

### Phase 3 — Multi-App, Multi-Platform & Client SDKs
- **Complete Client Libraries:** Ship tested, drop-in Kotlin (`AttestGateAppCheckProvider`) and Flutter (`MethodChannel` plugin) implementations with StrongBox-to-TEE fallback, automatic key cleanup, retry-on-403-expired-challenge, and strict TLS/network security configuration examples.
- **Multi-App Configuration:** Support a config file mapping multiple `(package_name, signing_cert_sha256)` tuples to distinct `FIREBASE_APP_ID`s from a single `attest-gate` deployment.
- **Cross-Platform Attestation:** Add an **Apple App Attest** verification flow (`/v1/ios/attest`) so a single self-hosted gateway can mint Firebase App Check tokens for both Android/GrapheneOS and iOS.
