use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signature as DalekSignature, Verifier as _, VerifyingKey};
use serde::Deserialize;
use ssh_key::{PublicKey as SshPublicKey, SshSig};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::state::{TrustAnchors, now_unix_secs};

pub const GOOGLE_CRL_URL: &str = "https://android.googleapis.com/attestation/status";
pub const GRAPHENEOS_KEYS_URL: &str = "https://grapheneos.org/attestation.json";
pub const GRAPHENEOS_SIG_URL: &str = "https://grapheneos.org/attestation.json.sig";

/// Official GrapheneOS OpenSSH Ed25519 signing key (`https://grapheneos.org/allowed_signers`).
pub const GRAPHENEOS_SSH_PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIUg/m5CoP83b0rfSCzYSVA4cw4ir49io5GPoxbgxdJE contact@grapheneos.org";
pub const GRAPHENEOS_SIG_NAMESPACE: &str = "attestation keys";

/// Sync interval when healthy: every 6 hours.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// Initial retry delay when any trust-anchor sync fails (doubles up to `RETRY_MAX_DELAY`).
const RETRY_INITIAL_DELAY: Duration = Duration::from_secs(10);
const RETRY_MAX_DELAY: Duration = Duration::from_secs(15 * 60);

/// Compile-time anti-rollback floor for GrapheneOS `attestation.json` timestamp across restarts.
pub const MIN_GRAPHENEOS_TIMESTAMP: u64 = 1_776_709_772;

/// Hard upper bounds on upstream sync payloads to prevent memory exhaustion.
const MAX_GOOGLE_CRL_BYTES: usize = 10 * 1024 * 1024; // 10 MiB
const MAX_GRAPHENEOS_JSON_BYTES: usize = 512 * 1024; // 512 KiB
const MAX_GRAPHENEOS_SIG_BYTES: usize = 16 * 1024; // 16 KiB

#[derive(Debug, Deserialize)]
struct GoogleCrlResponse {
    entries: HashMap<String, GoogleCrlEntry>,
}

#[derive(Debug, Deserialize)]
struct GoogleCrlEntry {
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrapheneOsAttestationPayload {
    pub verified_boot_keys: Vec<String>,
    pub timestamp: u64,
}

/// Runs an initial trust-anchor sync and then spawns a background task refreshing every 6 hours
/// (or retrying with exponential backoff whenever a required sync fails).
pub async fn start_sync_worker(
    http: reqwest::Client,
    trust_anchors: Arc<RwLock<TrustAnchors>>,
    allow_grapheneos: bool,
) {
    // Perform an initial sync on startup so trust anchors are warm immediately.
    let initial_ok = sync_once(&http, &trust_anchors, allow_grapheneos).await;

    tokio::spawn(async move {
        let mut backoff = if initial_ok {
            None
        } else {
            Some(RETRY_INITIAL_DELAY)
        };

        loop {
            let sleep_for = backoff.unwrap_or(SYNC_INTERVAL);
            tokio::time::sleep(sleep_for).await;

            let ok = sync_once(&http, &trust_anchors, allow_grapheneos).await;
            backoff = if ok {
                None
            } else {
                let next = backoff
                    .map(|d| d.saturating_mul(2).min(RETRY_MAX_DELAY))
                    .unwrap_or(RETRY_INITIAL_DELAY);
                warn!(retry_in_secs = next.as_secs(), "trust-anchor sync incomplete; scheduling retry");
                Some(next)
            };
        }
    });
}

/// Runs one sync pass across Google CRL and (if enabled) GrapheneOS keys.
/// Returns `true` iff all required feeds succeeded.
pub async fn sync_once(
    http: &reqwest::Client,
    trust_anchors: &Arc<RwLock<TrustAnchors>>,
    allow_grapheneos: bool,
) -> bool {
    let mut all_ok = true;

    match fetch_google_crl(http, GOOGLE_CRL_URL).await {
        Ok(revoked) => {
            let count = revoked.len();
            let mut guard = trust_anchors.write().await;
            guard.revoked_serials = revoked;
            guard.crl_last_synced_unix = Some(now_unix_secs());
            guard.crl_last_error = None;
            info!(revoked_count = count, "synchronized Google attestation CRL");
        }
        Err(err) => {
            all_ok = false;
            error!(error = %err, "failed to sync Google attestation CRL");
            let mut guard = trust_anchors.write().await;
            guard.crl_last_error = Some(err.to_string());
        }
    }

    if allow_grapheneos {
        let min_ts = trust_anchors
            .read()
            .await
            .grapheneos_timestamp
            .max(MIN_GRAPHENEOS_TIMESTAMP);
        match fetch_and_verify_grapheneos(
            http,
            GRAPHENEOS_KEYS_URL,
            GRAPHENEOS_SIG_URL,
            GRAPHENEOS_SSH_PUBKEY,
            min_ts,
        )
        .await
        {
            Ok((keys, timestamp)) => {
                let count = keys.len();
                let mut guard = trust_anchors.write().await;
                guard.grapheneos_keys = keys;
                guard.grapheneos_timestamp = timestamp;
                guard.grapheneos_last_synced_unix = Some(now_unix_secs());
                guard.grapheneos_last_error = None;
                info!(
                    key_count = count,
                    timestamp, "synchronized GrapheneOS verified boot keys"
                );
            }
            Err(err) => {
                all_ok = false;
                error!(error = %err, "failed to sync GrapheneOS verified boot keys");
                let mut guard = trust_anchors.write().await;
                guard.grapheneos_last_error = Some(err.to_string());
            }
        }
    } else {
        warn!("ALLOW_GRAPHENEOS=false; skipping GrapheneOS verified boot key sync");
    }

    all_ok
}

async fn read_bounded_body(
    mut resp: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            bail!(
                "{label} response Content-Length {len} exceeds maximum allowed size of {max_bytes} bytes"
            );
        }
    }

    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("failed reading chunk from {label}"))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            bail!("{label} response exceeded maximum allowed size of {max_bytes} bytes");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

pub async fn fetch_google_crl(http: &reqwest::Client, url: &str) -> Result<HashSet<String>> {
    let resp = http
        .get(url)
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .send()
        .await
        .context("HTTP GET Google CRL failed")?
        .error_for_status()
        .context("Google CRL returned non-2xx status")?;

    let body = read_bounded_body(resp, MAX_GOOGLE_CRL_BYTES, "Google CRL").await?;
    parse_google_crl(&body)
}

pub fn parse_google_crl(bytes: &[u8]) -> Result<HashSet<String>> {
    let parsed: GoogleCrlResponse =
        serde_json::from_slice(bytes).context("failed to parse Google CRL JSON")?;

    let mut revoked = HashSet::new();
    for (serial, entry) in parsed.entries {
        let status = entry.status.to_ascii_uppercase();
        if status == "REVOKED" || status == "SUSPENDED" {
            revoked.insert(normalize_hex_serial(&serial));
        }
    }
    Ok(revoked)
}

/// Normalizes a hex certificate serial number to lowercase without leading zeros
/// (matching Google's attestation status list format `^[a-f1-9][a-f0-9]*$`).
pub fn normalize_hex_serial(serial: &str) -> String {
    let lower = serial.trim().to_ascii_lowercase();
    let stripped = lower.trim_start_matches('0');
    if stripped.is_empty() {
        "0".to_string()
    } else {
        stripped.to_string()
    }
}

pub async fn fetch_and_verify_grapheneos(
    http: &reqwest::Client,
    json_url: &str,
    sig_url: &str,
    expected_ssh_pubkey: &str,
    min_timestamp: u64,
) -> Result<(HashSet<String>, u64)> {
    let (json_res, sig_res) = tokio::join!(
        http.get(json_url).send(),
        http.get(sig_url).send(),
    );

    let json_resp = json_res
        .context("HTTP GET GrapheneOS attestation.json failed")?
        .error_for_status()
        .context("GrapheneOS attestation.json returned non-2xx status")?;
    let json_bytes =
        read_bounded_body(json_resp, MAX_GRAPHENEOS_JSON_BYTES, "GrapheneOS attestation.json")
            .await?;

    let sig_resp = sig_res
        .context("HTTP GET GrapheneOS attestation.json.sig failed")?
        .error_for_status()
        .context("GrapheneOS attestation.json.sig returned non-2xx status")?;
    let sig_bytes = read_bounded_body(
        sig_resp,
        MAX_GRAPHENEOS_SIG_BYTES,
        "GrapheneOS attestation.json.sig",
    )
    .await?;

    verify_and_parse_grapheneos(&json_bytes, &sig_bytes, expected_ssh_pubkey, min_timestamp)
}

/// Verifies the OpenSSH `SSHSIG` signature on `attestation.json`, enforces monotonic `timestamp`,
/// and extracts normalized lowercase hex verified boot keys.
pub fn verify_and_parse_grapheneos(
    json_bytes: &[u8],
    sig_bytes: &[u8],
    expected_ssh_pubkey: &str,
    min_timestamp: u64,
) -> Result<(HashSet<String>, u64)> {
    let expected_key = SshPublicKey::from_openssh(expected_ssh_pubkey)
        .context("invalid pinned GrapheneOS OpenSSH public key")?;

    let ssh_sig =
        SshSig::from_pem(sig_bytes).context("failed to parse GrapheneOS SSHSIG signature PEM")?;

    // 1. Verify the signature was produced by the exact pinned public key.
    if ssh_sig.public_key() != expected_key.key_data() {
        bail!("GrapheneOS signature public key does not match pinned contact@grapheneos.org key");
    }

    // 2. Verify namespace matches "attestation keys".
    if ssh_sig.namespace() != GRAPHENEOS_SIG_NAMESPACE {
        bail!(
            "unexpected GrapheneOS signature namespace '{}', expected '{}'",
            ssh_sig.namespace(),
            GRAPHENEOS_SIG_NAMESPACE
        );
    }

    // 3. Verify cryptographic Ed25519 signature over the SSHSIG signed data payload
    //    using both `ssh-key` and `ed25519-dalek`.
    expected_key
        .verify(GRAPHENEOS_SIG_NAMESPACE, json_bytes, &ssh_sig)
        .context("GrapheneOS OpenSSH signature verification failed")?;

    let ed_pub = expected_key
        .key_data()
        .ed25519()
        .context("expected Ed25519 public key for GrapheneOS")?;
    let verifying_key = VerifyingKey::from_bytes(&ed_pub.0)
        .context("invalid Ed25519 verifying key bytes")?;
    let signed_data = SshSig::signed_data(
        GRAPHENEOS_SIG_NAMESPACE,
        ssh_sig.hash_alg(),
        json_bytes,
    )
    .context("failed to construct SSHSIG signed data")?;
    let sig_slice = ssh_sig.signature_bytes();
    let dalek_sig = DalekSignature::from_slice(sig_slice)
        .context("invalid Ed25519 signature length in SSHSIG")?;
    verifying_key
        .verify(&signed_data, &dalek_sig)
        .context("ed25519-dalek verification of GrapheneOS signature failed")?;

    // 4. Parse JSON payload and enforce monotonic timestamp check (anti-rollback).
    let payload: GrapheneOsAttestationPayload = serde_json::from_slice(json_bytes)
        .context("failed to parse GrapheneOS attestation.json")?;

    if payload.timestamp == 0 {
        bail!("GrapheneOS attestation.json timestamp must be non-zero");
    }
    if payload.timestamp < min_timestamp {
        bail!(
            "GrapheneOS attestation.json timestamp regression detected: got {}, previous was {}",
            payload.timestamp,
            min_timestamp
        );
    }

    let mut keys = HashSet::with_capacity(payload.verified_boot_keys.len());
    for key in payload.verified_boot_keys {
        let normalized = key.trim().to_ascii_lowercase();
        if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("invalid verifiedBootKey digest '{}' in GrapheneOS feed", key);
        }
        keys.insert(normalized);
    }

    if keys.is_empty() {
        bail!("GrapheneOS attestation.json contained zero verifiedBootKeys");
    }

    Ok((keys, payload.timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{HashAlg, LineEnding, PrivateKey};

    #[test]
    fn verifies_valid_grapheneos_sshsig_and_enforces_monotonic_timestamp() {
        // Generate an ephemeral Ed25519 SSH keypair for unit testing SSHSIG verification.
        let mut rng = rand::thread_rng();
        let priv_key = PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519).unwrap();
        let pub_openssh = priv_key.public_key().to_openssh().unwrap();

        let payload = br#"{"verifiedBootKeys":["d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80"],"timestamp":1776709772}"#;
        let sig = priv_key
            .sign(GRAPHENEOS_SIG_NAMESPACE, HashAlg::Sha512, payload)
            .unwrap();
        let sig_pem = sig.to_pem(LineEnding::LF).unwrap();

        // Valid verification succeeds.
        let (keys, ts) =
            verify_and_parse_grapheneos(payload, sig_pem.as_bytes(), &pub_openssh, 0).unwrap();
        assert_eq!(ts, 1776709772);
        assert!(keys.contains("d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80"));

        // Same timestamp is allowed on periodic re-sync.
        assert!(
            verify_and_parse_grapheneos(payload, sig_pem.as_bytes(), &pub_openssh, 1776709772)
                .is_ok()
        );

        // Older timestamp (rollback attack) is rejected.
        let err =
            verify_and_parse_grapheneos(payload, sig_pem.as_bytes(), &pub_openssh, 1776709773)
                .unwrap_err();
        assert!(err.to_string().contains("regression"));

        // Tampered payload is rejected.
        let tampered = br#"{"verifiedBootKeys":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"timestamp":1776709772}"#;
        assert!(
            verify_and_parse_grapheneos(tampered, sig_pem.as_bytes(), &pub_openssh, 0).is_err()
        );

        // Wrong namespace is rejected.
        let wrong_ns_sig = priv_key
            .sign("factory images", HashAlg::Sha512, payload)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap();
        assert!(
            verify_and_parse_grapheneos(payload, wrong_ns_sig.as_bytes(), &pub_openssh, 0)
                .is_err()
        );
    }

    #[test]
    fn parses_google_crl_revoked_and_suspended_entries() {
        let raw = br#"{
            "entries": {
                "2c8cdddfd5e03bfc": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
                "00C8966FCB2FBB0D7A": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW"},
                "abcdef": {"status": "ACTIVE"}
            }
        }"#;
        let revoked = parse_google_crl(raw).unwrap();
        assert!(revoked.contains("2c8cdddfd5e03bfc"));
        assert!(revoked.contains("c8966fcb2fbb0d7a"));
        assert!(!revoked.contains("abcdef"));
    }

    #[test]
    fn pinned_grapheneos_pubkey_parses() {
        let key = SshPublicKey::from_openssh(GRAPHENEOS_SSH_PUBKEY).unwrap();
        assert!(key.key_data().ed25519().is_some());
    }
}
