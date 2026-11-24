use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use dashmap::DashMap;
use rand::RngCore;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::config::Config;
use crate::firebase::FirebaseClient;

pub const CHALLENGE_TTL_SECS: u64 = 60;
pub const DEFAULT_MAX_CHALLENGES: usize = 10_000;
/// Maximum allowed age of the Google CRL before attestations fail closed (48 hours).
pub const MAX_CRL_AGE_SECS: u64 = 48 * 60 * 60;
const CHALLENGE_BYTES_LEN: usize = 32;

/// In-memory store for single-use 32-byte attestation challenges with strict 60s TTL
/// and a hard capacity cap to prevent OOM denial of service.
#[derive(Debug)]
pub struct ChallengeStore {
    entries: DashMap<String, Instant>,
    max_entries: usize,
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::with_max_entries(DEFAULT_MAX_CHALLENGES)
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Generates a cryptographically random 32-byte base64url challenge and stores its expiry.
    /// Returns `None` if the store is at capacity even after evicting expired entries.
    pub fn issue(&self) -> Option<(String, u64)> {
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
            if self.entries.len() >= self.max_entries {
                return None;
            }
        }
        let mut nonce = [0u8; CHALLENGE_BYTES_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let encoded = URL_SAFE_NO_PAD.encode(nonce);
        let expires_at = Instant::now() + Duration::from_secs(CHALLENGE_TTL_SECS);
        self.entries.insert(encoded.clone(), expires_at);
        Some((encoded, CHALLENGE_TTL_SECS))
    }

    /// Inserts a known challenge directly (used in tests).
    pub fn insert_with_ttl(&self, challenge_b64url: String, ttl: Duration) {
        self.entries
            .insert(challenge_b64url, Instant::now() + ttl);
    }

    /// Atomically removes and validates a challenge, returning its raw 32 bytes if valid & unexpired.
    pub fn consume(&self, challenge_b64url: &str) -> Option<Vec<u8>> {
        let (_, expires_at) = self.entries.remove(challenge_b64url)?;
        if Instant::now() > expires_at {
            return None;
        }
        URL_SAFE_NO_PAD.decode(challenge_b64url).ok()
    }

    /// Removes expired challenges to keep memory bounded.
    pub fn evict_expired(&self) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries.retain(|_, exp| *exp > now);
        before.saturating_sub(self.entries.len())
    }

    pub fn active_count(&self) -> usize {
        self.entries.len()
    }
}

/// Synchronized Google CRL and GrapheneOS verified boot keys.
#[derive(Debug, Default)]
pub struct TrustAnchors {
    /// Lowercase hex certificate serial numbers (without leading zeros) marked REVOKED or SUSPENDED.
    pub revoked_serials: HashSet<String>,
    pub crl_last_synced_unix: Option<u64>,
    pub crl_last_error: Option<String>,

    /// Lowercase hex verified boot keys from GrapheneOS signed attestation.json.
    pub grapheneos_keys: HashSet<String>,
    /// Monotonic timestamp from the latest accepted GrapheneOS attestation.json.
    pub grapheneos_timestamp: u64,
    pub grapheneos_last_synced_unix: Option<u64>,
    pub grapheneos_last_error: Option<String>,
}

/// Public readiness summary for a trust-anchor feed (intentionally omits internal error strings).
#[derive(Debug, Serialize)]
pub struct SyncComponentStatus {
    pub synced: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
}

impl TrustAnchors {
    pub fn is_crl_fresh(&self, now_unix: u64) -> bool {
        self.crl_last_synced_unix
            .is_some_and(|ts| now_unix.saturating_sub(ts) <= MAX_CRL_AGE_SECS)
    }

    pub fn crl_status(&self, now_unix: u64) -> SyncComponentStatus {
        let synced = self.crl_last_synced_unix.is_some();
        let stale = synced && !self.is_crl_fresh(now_unix);
        SyncComponentStatus {
            synced,
            stale: Some(stale),
        }
    }

    pub fn grapheneos_status(&self) -> SyncComponentStatus {
        SyncComponentStatus {
            synced: self.grapheneos_last_synced_unix.is_some(),
            stale: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub challenges: Arc<ChallengeStore>,
    pub trust_anchors: Arc<RwLock<TrustAnchors>>,
    pub firebase: Arc<FirebaseClient>,
}

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_store_enforces_max_capacity_and_reclaims_expired() {
        let store = ChallengeStore::with_max_entries(2);
        assert!(store.issue().is_some());
        assert!(store.issue().is_some());
        // Full -> rejected.
        assert!(store.issue().is_none());

        // Replace with expired entry and verify issue() evicts expired slots.
        let store2 = ChallengeStore::with_max_entries(1);
        store2.insert_with_ttl("expired".into(), Duration::ZERO);
        std::thread::sleep(Duration::from_millis(5));
        assert!(store2.issue().is_some());
    }

    #[test]
    fn trust_anchors_detect_stale_crl() {
        let mut anchors = TrustAnchors::default();
        assert!(!anchors.is_crl_fresh(2_000_000_000));

        anchors.crl_last_synced_unix = Some(2_000_000_000);
        assert!(anchors.is_crl_fresh(2_000_000_000 + MAX_CRL_AGE_SECS));
        assert!(!anchors.is_crl_fresh(2_000_000_000 + MAX_CRL_AGE_SECS + 1));
    }
}
