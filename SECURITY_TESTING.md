# Security Verification & Bug Reproduction Guide

This guide explains how you can reproduce each of the security flaws that existed in the initial version of `attest-gate`—and verify that the fixes block them—using your own **PC** and **Android / GrapheneOS phone** against your own local or staging `attest-gate` instance.

> **Authorized Self-Testing Only:** Run these checks strictly against your own local/staging `attest-gate` deployment and your own devices.

---

## Prerequisites

- **On your PC:**
  - `curl`, `jq`, `podman` (or `docker`), and `python3` (optional, for quick scripting).
  - The repository checked out locally.
- **On your Android phone (for Test 1 — End-to-End Hardware Chain Verification):**
  - Any physical Android 8.0+ phone (stock Android or GrapheneOS, locked or unlocked) with Android Studio / ADB if you want to build the minimal Android Keystore test app.
  - Alternatively, you can reproduce Test 1 entirely on your PC via `cargo test` using synthetic X.509 chains that mirror real Android Keystore leaf certificates.

---

## 0. Fast Automated Verification (PC Only)

Every security fix has a dedicated regression test. Run the full suite inside the Rust container on your PC:

```bash
podman run --rm \
  -v "$PWD:/work:Z" \
  -v "$HOME/.cargo/registry:/usr/local/cargo/registry:Z" \
  -w /work \
  docker.io/library/rust:1-bookworm \
  cargo test --locked
```

Key regression tests to watch in the output:
- `attestation::tests::rejects_forged_leaf_signed_by_real_end_entity_keystore_leaf`
- `attestation::tests::rejects_ca_without_key_cert_sign_and_pathlen_violation_and_ca_leaf`
- `attestation::tests::rejects_stale_crl_and_all_zero_verified_boot_key`
- `rate_limit::tests::xff_mode_uses_rightmost_hop_and_ignores_spoofed_leftmost_and_cf_header`
- `rate_limit::tests::caps_bucket_map_to_prevent_oom`
- `state::tests::challenge_store_enforces_max_capacity_and_reclaims_expired`
- `config::tests::redacts_private_key_in_debug_output`
- `healthz_livez_and_challenge_endpoints_work` (integration)
- `rate_limiter_blocks_burst_excess_and_spoofed_xff_while_exempting_health_probes` (integration)

---

## 1. CRITICAL — Forged Leaf Signed by a Real Android Keystore Leaf (`BasicConstraints` / `KeyUsage` / `pathLenConstraint` Bypass)

### Why the Old Code Was Vulnerable
In the initial version, `src/attestation.rs` checked:
```rust
match issuer.basic_constraints() {
    Ok(Some(bc)) if !bc.value.ca => return Err(...),
    Err(e) => return Err(...),
    _ => {} // <-- BUG: silently allowed Ok(None)!
}
```
Real Android Keystore leaf attestation certificates **omit `BasicConstraints`** and only have `KeyUsage: digitalSignature` (never `keyCertSign`). Because `Ok(None)` was accepted and neither `KeyUsage::keyCertSign` nor `pathLenConstraint` was checked, **any** Android Keystore signing key from **any** app on **any** physical Android device could sign a forged child certificate containing arbitrary `KeyDescription` claims!

### How You Would Reproduce It With Your Phone + PC (Against an Unpatched Build)

1. **On your Android phone (any app, even a debug app or unlocked bootloader):**
   - Generate an EC P-256 signing key inside `AndroidKeyStore` with `PURPOSE_SIGN`, `DIGEST_SHA256`, and any dummy `setAttestationChallenge("dummy".toByteArray())`:
     ```kotlin
     val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
     kpg.initialize(
         KeyGenParameterSpec.Builder("test_signer", KeyProperties.PURPOSE_SIGN)
             .setDigests(KeyProperties.DIGEST_SHA256)
             .setAttestationChallenge("dummy".toByteArray())
             .build()
     )
     kpg.generateKeyPair()
     val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
     val realChain = ks.getCertificateChain("test_signer") // [real_leaf, batch_ca, google_inter, google_root]
     ```
   - Inspect `realChain[0]` (`real_leaf`) on your PC with `openssl x509 -text -noout`: you will see it has **no `X509v3 Basic Constraints`** extension and `Key Usage: Digital Signature`.
2. **Fetch a fresh challenge from your `attest-gate` server:**
   ```bash
   CHALLENGE=$(curl -s -X POST http://localhost:8080/v1/challenge | jq -r .challenge)
   ```
3. **Construct & sign a forged leaf certificate (`forged_leaf`) using `test_signer` in Android Keystore:**
   - Build a TBS X.509v3 certificate whose:
     - `issuer` matches `real_leaf.subject` (typically `CN=Android Keystore Key`),
     - `validity` is current,
     - custom extension `1.3.6.1.4.1.11129.2.1.17` embeds a DER `KeyDescription` containing:
       - `attestationSecurityLevel = 2` (`StrongBox`), `keymasterSecurityLevel = 2`,
       - `attestationChallenge = base64url_decode($CHALLENGE)`,
       - `teeEnforced[704]` (`RootOfTrust`): `deviceLocked = true`, `verifiedBootState = 0` (`Verified`), non-zero 32-byte `verifiedBootKey`,
       - `softwareEnforced[709]` (`attestationApplicationId`): your target `ALLOWED_PACKAGE_NAME` + your target `ALLOWED_SIGNING_CERT_SHA256`.
   - Sign the TBS certificate bytes using `Signature.getInstance("SHA256withECDSA")` initialized with `ks.getKey("test_signer", null) as PrivateKey`.
4. **Submit the 4-certificate extended chain `[forged_leaf, real_leaf, batch_ca, ..., google_root]`:**
   ```bash
   curl -i -X POST http://localhost:8080/v1/attest \
     -H "Content-Type: application/json" \
     -d '{
       "challenge": "'"$CHALLENGE"'",
       "certificate_chain": ["<b64 forged_leaf>", "<b64 real_leaf>", "<b64 batch_ca>", "<b64 google_root>"]
     }'
   ```

### Expected Behavior
- **Unpatched build:** Returns **`200 OK`** and mints a genuine Firebase App Check JWT even though the request came from a completely different app (or unlocked phone).
- **Fixed build:** Returns **`403 Forbidden`** with `{"error":"attestation_failed","message":"Attestation verification failed"}`, and server logs record:
  `certificate[1] is missing required BasicConstraints extension` (and even if `BasicConstraints` were somehow present, `KeyUsage::keyCertSign` and `batch_ca`'s `pathLenConstraint=0` also reject it).

---

## 2. HIGH — Rate-Limit Bypass via `X-Forwarded-For` / `CF-Connecting-IP` Spoofing (PC Only)

### Why the Old Code Was Vulnerable
The old code defaulted to `TRUST_PROXY_HEADERS=true`, read the **leftmost** entry in `X-Forwarded-For` (which any client can prepend before the reverse proxy appends the real client IP), and prioritized `CF-Connecting-IP` unconditionally.

### How to Reproduce From Your PC
Assuming default `RATE_LIMIT_BURST=20` and a local instance running on `http://localhost:8080` behind a proxy (or with `PROXY_IP_MODE=xff` simulating a proxy appending your real IP `198.51.100.5` on the right):

```bash
for i in $(seq 1 25); do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/v1/challenge \
    -H "X-Forwarded-For: 10.0.0.$i, 198.51.100.5" \
    -H "CF-Connecting-IP: 10.0.1.$i")
  echo "req $i -> HTTP $CODE"
done
```

### Expected Behavior
- **Unpatched build:** Every single request (`1..25`, and indefinitely) returns **`200`** because each request looks like a brand-new IP (`10.0.0.1`, `10.0.0.2`, ...).
- **Fixed build (`PROXY_IP_MODE=direct` or `PROXY_IP_MODE=xff`):** Requests `1..20` return **`200`**, and requests `21..25` return **`429 Too Many Requests`** with a `Retry-After` header, because spoofed leftmost `X-Forwarded-For` entries and `CF-Connecting-IP` are ignored.

---

## 3. HIGH — OOM DoS via Unbounded `ChallengeStore` & `IpRateLimiter` Maps (PC Only)

### Why the Old Code Was Vulnerable
Neither `ChallengeStore` nor `IpRateLimiter` enforced a maximum entry count. Combined with spoofed IPs and the Kubernetes `128Mi` memory limit, rapid `POST /v1/challenge` calls could exhaust container RAM and trigger OOMKills.

### How to Test Safely on Your PC
1. Run the deterministic unit tests that exercise the exact cap enforcement without needing to allocate hundreds of megabytes:
   ```bash
   # Inside the Rust container:
   cargo test --locked challenge_store_enforces_max_capacity
   cargo test --locked caps_bucket_map_to_prevent_oom
   ```
2. Optionally, run your local container with a strict memory cap (`podman run --rm --memory=128m ...`) and send a burst of requests with `PROXY_IP_MODE=direct` (or `xff`) to confirm memory stays flat and requests hit `429` (rate limit) or `503` (challenge store cap at `10,000` active entries) rather than crashing the process.

---

## 4. MEDIUM — `/healthz` Always Returning `200 OK` When Degraded & Leaking Metadata (PC Only)

### Why the Old Code Was Vulnerable
In the old code, `GET /healthz` always returned HTTP `200 OK` even when Google CRL sync had failed (`status: "degraded"`), causing Kubernetes readiness probes to route traffic to a broken pod. It also leaked raw `last_error` strings and live `active_challenges` counts.

### How to Reproduce From Your PC
Start a local container with **no internet access** (`--network=none`) or blocked egress so initial CRL sync fails, then query `/healthz` and `/livez`:

```bash
# Example using a temporary podman network with --internal (no internet egress):
podman network create --internal attest-no-egress
podman run --rm --name attest-test --network attest-no-egress -p 8080:8080 \
  -v /path/to/dummy-sa.json:/secrets/firebase-sa.json:ro \
  -e GOOGLE_APPLICATION_CREDENTIALS=/secrets/firebase-sa.json \
  -e FIREBASE_PROJECT_NUMBER=123456789012 \
  -e FIREBASE_APP_ID=1:123456789012:android:abcdef123456 \
  -e ALLOWED_PACKAGE_NAME=com.example.app \
  -e ALLOWED_SIGNING_CERT_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  attest-gate:test
```

Then from another terminal:
```bash
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/livez
```

### Expected Behavior
- **Unpatched build:** `/healthz` returned **`HTTP/1.1 200 OK`** with `"status": "degraded"`, raw `"last_error": "HTTP GET Google CRL failed..."`, and `"active_challenges": 0`. And in server logs, it would not retry for **6 hours**.
- **Fixed build:**
  - `/healthz` returns **`HTTP/1.1 503 Service Unavailable`** with `{"status":"degraded","google_crl":{"synced":false,"stale":false},"grapheneos":{"synced":false}}` (no `last_error`, no `active_challenges`).
  - `/livez` returns **`HTTP/1.1 200 OK`** with `{"status":"ok"}` (so Kubernetes `livenessProbe` does not restart-loop the pod).
  - Server logs show exponential backoff retries (`retry_in_secs=10`, `20`, `40`, ...) instead of sleeping 6 hours.

---

## 5. MEDIUM — Wildcard CORS Header (`Access-Control-Allow-Origin: *`) (PC Only)

### How to Reproduce From Your PC
```bash
curl -i -H "Origin: https://evil.example" http://localhost:8080/healthz
```

### Expected Behavior
- **Unpatched build:** Response includes `access-control-allow-origin: *`.
- **Fixed build:** No `access-control-allow-origin` header is returned.

---

## 6. MEDIUM — Verbose `403 Forbidden` Error Messages Leaking `ALLOWED_PACKAGE_NAME` (PC Only)

### How to Reproduce From Your PC
Send an invalid attestation payload (or a real attestation from a different package name on your phone):

```bash
curl -i -X POST http://localhost:8080/v1/attest \
  -H "Content-Type: application/json" \
  -d '{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","certificate_chain":["AA==","AA=="]}'
```

### Expected Behavior
- **Unpatched build:** Returned detailed internal rejection strings in the JSON `message` field (and on package mismatch, literally echoed `ALLOWED_PACKAGE_NAME '<your.package.name>'`).
- **Fixed build:** Always returns `{"error":"attestation_failed","message":"Attestation verification failed"}` to the client while logging the exact diagnostic `reason` in server-side structured JSON logs.

---

## 7. MEDIUM — `ServiceAccountCredentials` `Debug` Private Key Redaction (PC Only)

### Why the Old Code Was Vulnerable
`ServiceAccountCredentials` derived `#[derive(Debug)]`, so formatting `Config` or `ServiceAccountCredentials` with `{:?}` printed the full `private_key` PEM.

### How to Verify
Run the dedicated unit test:
```bash
cargo test --locked redacts_private_key_in_debug_output
```
It asserts that `format!("{creds:?}")` contains `[REDACTED]` and never contains the private key string.
