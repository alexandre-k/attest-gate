[![Rust](https://github.com/alexandre-k/attest-gate/actions/workflows/rust.yml/badge.svg)](https://github.com/alexandre-k/attest-gate/actions/workflows/rust.yml)
[![Container](https://github.com/alexandre-k/attest-gate/actions/workflows/docker-image.yml/badge.svg)](https://github.com/alexandre-k/attest-gate/actions/workflows/docker-image.yml)

# `attest-gate`

Self-hosted Rust microservice that replaces **Google Play Integrity** with **Android Hardware Key Attestation** (supporting both **stock Android** and **GrapheneOS**) and mints official **Firebase App Check** JWTs for **Firebase AI Logic (Gemini / Vertex AI in Firebase)**—with zero dependency on Google Play Services or the Play Store.

> For a deep dive into the threat model, what is and isn't guaranteed, operational behavior, and roadmap, see [DOCUMENTATION.md](DOCUMENTATION.md). For vulnerability reporting, see [SECURITY.md](SECURITY.md). For hands-on security verification tests, see [SECURITY_TESTING.md](SECURITY_TESTING.md).

---

## Architecture

```text
Android / GrapheneOS App (no Play Services)
  │
  │ 1. POST /v1/challenge
  ├─────────────────────────────────────────► attest-gate (Rust / k3s)
  │◄────────────────── 32B base64url nonce ───┤   - Bounded DashMap (60s single-use TTL)
  │                                           │   - Google CRL sync (every 6h, 48h max staleness)
  │ 2. AndroidKeyStore EC P-256 keygen        │   - GrapheneOS SSHSIG key sync (every 6h)
  │    (StrongBox -> TEE fallback)            │   - Bounded per-IP token-bucket rate limiter
  │    + getCertificateChain + deleteEntry    │
  │                                           │
  │ 3. POST /v1/attest (nonce + DER chain)    │
  ├─────────────────────────────────────────► │ 4. Verify X.509 CA chain (BasicConstraints,
  │                                           │    pathLen, KeyUsage) & Google Root SPKI
  │                                           │    Check CRL + KeyDescription (OID ...2.1.17)
  │                                           │    Check RootOfTrust [704] & AppId [709]
  │                                           │
  │                                           │ 5. Exchange RS256 Custom JWT (cached OAuth2)
  │                                           ├──────────► Firebase App Check REST API
  │◄──────── Official Firebase App Check JWT ─┤◄────────── (exchangeCustomToken)
  │
  │ 6. Call Firebase AI Logic (Gemini) with X-Firebase-AppCheck header enforced
  └─────────────────────────────────────────────────────────────────────────► Firebase AI
```

---

## Repository Layout

- `src/` — Rust microservice (`edition = "2024"`, MSRV **Rust 1.85+**)
  - `src/attestation.rs` — Full hardware attestation & RFC 5280 X.509 chain verification pipeline
  - `src/roots.rs` — Pinned Google RSA-4096 & ECDSA P-384 (`Key Attestation CA1`) hardware root SPKIs
  - `src/sync.rs` — 6-hour background sync (with exponential backoff retry and bounded response reads) for Google CRL and OpenSSH-verified GrapheneOS verified boot keys (with monotonic `timestamp` anti-rollback protection)
  - `src/firebase.rs` — 50-minute OAuth2 bearer token cache + RS256 custom JWT signing + `:exchangeCustomToken`
  - `src/rate_limit.rs` — Bounded per-IP `DashMap` token-bucket rate limiter with spoofing-resistant proxy IP modes
  - `src/routes.rs` — `GET /livez`, `GET /healthz`, `POST /v1/challenge`, `POST /v1/attest`
  - `src/config.rs`, `src/state.rs`, `src/error.rs`, `src/main.rs`
- `tests/` — HTTP & JWT integration tests (`tests/api_integration.rs`)
- `Containerfile` — Multi-stage Podman/Docker build (`--locked`) targeting `gcr.io/distroless/cc-debian12:nonroot` (UID `65532`)
- `k8s/` — Kubernetes (`k3s`) manifests (`deployment.yaml`, `service.yaml`, `secret.example.yaml`)
- `DOCUMENTATION.md` — Architecture, threat model, limitations, and roadmap
- `SECURITY.md` — Security policy and vulnerability reporting
- `SECURITY_TESTING.md` — How to reproduce and verify security test cases on your PC & Android device
- `LICENSE` — Apache License 2.0

---

## HTTP Endpoints

| Method & Path | Purpose |
| --- | --- |
| `GET /livez` | Liveness probe (`200 OK` while HTTP runtime is healthy; rate-limit exempt) |
| `GET /healthz` | Readiness probe (`200 OK` when trust anchors are synced & fresh, `503 Service Unavailable` otherwise; rate-limit exempt) |
| `POST /v1/challenge` | Issues a single-use 32-byte base64url challenge nonce (`60s` TTL) |
| `POST /v1/attest` | Verifies hardware key attestation chain + nonce and returns an official Firebase App Check JWT (standard session token by default, or single-use limited-use token when `"limited_use": true`) |

---

## Environment Variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `GOOGLE_APPLICATION_CREDENTIALS` | Yes | — | Path to Firebase Service Account JSON (e.g. `/secrets/firebase-sa.json`) |
| `FIREBASE_PROJECT_NUMBER` | Yes | — | Numeric Firebase / GCP project number (e.g. `123456789012`) |
| `FIREBASE_APP_ID` | Yes | — | Full Firebase Android App ID (e.g. `1:123456789012:android:abcdef`) |
| `ALLOWED_PACKAGE_NAME` | Yes | — | Expected Android application ID (e.g. `com.example.app`) |
| `ALLOWED_SIGNING_CERT_SHA256` | Yes | — | Comma-separated lowercase hex SHA-256 digests of release APK signing certs |
| `ALLOW_GRAPHENEOS` | No | `true` | Allow `SelfSigned` verified boot when key matches GrapheneOS signed feed |
| `BIND_ADDR` | No | `0.0.0.0:8080` | TCP bind address (plain HTTP; terminate TLS at your ingress/proxy) |
| `RATE_LIMIT_RPM` | No | `60` | Sustained per-IP requests per minute |
| `RATE_LIMIT_BURST` | No | `20` | Per-IP token-bucket burst size |
| `PROXY_IP_MODE` | No | `direct` | Client IP extraction mode: `direct`, `xff` (rightmost untrusted `X-Forwarded-For`), or `cloudflare` (`CF-Connecting-IP`, **only** when origin blocks non-Cloudflare IPs) |
| `TRUSTED_PROXY_HOPS` | No | `1` | Number of trusted reverse proxies appending to `X-Forwarded-For` when `PROXY_IP_MODE=xff` |
| `TRUST_PROXY_HEADERS` | No | `false` | Legacy fallback boolean (`true` maps to `PROXY_IP_MODE=xff` when `PROXY_IP_MODE` is unset) |

---

## Setup Checklist

### 1. Google Cloud IAM & Service Account
1. In **Google Cloud Console → APIs & Services**, enable the **Firebase App Check API** (`firebaseappcheck.googleapis.com`).
2. Create a **dedicated** Service Account solely for `attest-gate` (e.g. `attest-gate@<project-id>.iam.gserviceaccount.com`).
   - Because Firebase App Check's REST API requires the `https://www.googleapis.com/auth/cloud-platform` OAuth2 scope, IAM roles are the permission boundary—do not reuse a broadly privileged service account.
3. Grant the Service Account the minimum IAM permissions required to exchange custom App Check tokens (start with `roles/firebaseappcheck.tokenVerifier`; if `:exchangeCustomToken` returns `403 PERMISSION_DENIED` under your org policy, grant `roles/firebaseappcheck.admin` or `roles/iam.serviceAccountTokenCreator` as needed).
4. Create and download a JSON private key for the Service Account.
5. Create the Kubernetes `Secret` in your cluster (**never** commit the JSON file or real `secret.yaml` to Git):
   ```bash
   kubectl create secret generic firebase-sa-secret \
     --from-file=firebase-sa.json=/path/to/firebase-sa.json
   ```

### 2. Extract & Register Release APK Signing Certificate SHA-256
Extract the SHA-256 digest of your release APK signing certificate:
```bash
# Option A: from a signed release APK
apksigner verify --print-certs app-release.apk | grep "SHA-256 digest"

# Option B: from your release keystore
keytool -list -v -keystore release.jks -alias your-key-alias | grep SHA256
```
Strip colons and lowercase the 64-character hex digest (`attest-gate` also normalizes colons/uppercase automatically), then set `ALLOWED_SIGNING_CERT_SHA256` in your deployment manifest. Also register the SHA-256 fingerprint under **Firebase Console → Project Settings → Your Android App → SHA certificate fingerprints**.

### 3. Build, Test & Deploy to Kubernetes (`k3s`)
Run the test suite (requires Rust 1.85+ or the official `rust:1-bookworm` container):
```bash
cargo test --locked
```

Build and push the distroless container image:
```bash
podman build -f Containerfile -t ghcr.io/your-org/attest-gate:latest .
podman push ghcr.io/your-org/attest-gate:latest
```

Update `image`, `FIREBASE_PROJECT_NUMBER`, `FIREBASE_APP_ID`, `ALLOWED_PACKAGE_NAME`, `ALLOWED_SIGNING_CERT_SHA256`, and `PROXY_IP_MODE` in `k8s/deployment.yaml`, then apply:
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
```
- **Single Replica:** Keep `replicas: 1` while challenges are stored in an in-memory `DashMap`.
- **TLS Required:** Expose `attest-gate` strictly over HTTPS via your ingress controller so challenges and App Check JWTs are never exposed in transit.

Verify readiness via `/healthz`:
```bash
curl -s https://attest.example.com/healthz | jq .
```

### 4. Enable App Check Enforcement for Firebase AI Logic
1. Open **Firebase Console → Build → App Check → Apps** and register your Android app (Play Integrity is not required; custom tokens signed by your project's Service Account are accepted automatically).
2. Open **Firebase Console → Build → App Check → APIs → Firebase AI Logic** (formerly *Vertex AI in Firebase*).
3. Implement a custom Firebase App Check provider in your Android/Flutter client that fetches `/v1/challenge`, generates an ephemeral `AndroidKeyStore` EC P-256 key (`StrongBox` with `TEE` fallback) using the nonce as `attestationChallenge`, submits the Base64 DER certificate chain to `/v1/attest`, deletes the ephemeral key, and returns the minted JWT + expiration to the Firebase App Check SDK.
4. Observe **Unenforced (Metrics)** first until you see verified traffic from both stock Android and GrapheneOS devices, then click **Enforce**.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
