use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// Google Cloud / Firebase Service Account JSON credentials.
#[derive(Clone, Deserialize)]
pub struct ServiceAccountCredentials {
    pub client_email: String,
    pub private_key: String,
    #[serde(default)]
    pub private_key_id: Option<String>,
    #[serde(default = "default_token_uri")]
    pub token_uri: String,
}

impl fmt::Debug for ServiceAccountCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountCredentials")
            .field("client_email", &self.client_email)
            .field("private_key", &"[REDACTED]")
            .field("private_key_id", &self.private_key_id)
            .field("token_uri", &self.token_uri)
            .finish()
    }
}

/// Strategy for determining client IP addresses for rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyIpMode {
    /// Ignore all proxy headers and use the direct TCP peer IP (`ConnectInfo<SocketAddr>`).
    Direct,
    /// Extract the rightmost untrusted IP from `X-Forwarded-For` given `trusted_hops` reverse
    /// proxies (falling back to `X-Real-IP`, then TCP peer IP).
    Xff { trusted_hops: usize },
    /// Extract from `CF-Connecting-IP` (only safe when origin ingress restricts traffic strictly
    /// to Cloudflare IPs), falling back to rightmost `X-Forwarded-For`, then TCP peer IP.
    Cloudflare,
}

fn default_token_uri() -> String {
    "https://oauth2.googleapis.com/token".to_string()
}

/// Runtime configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct Config {
    pub google_application_credentials: PathBuf,
    pub service_account: ServiceAccountCredentials,
    pub firebase_project_number: String,
    pub firebase_app_id: String,
    pub allowed_package_name: String,
    pub allowed_signing_cert_sha256: HashSet<String>,
    pub allow_grapheneos: bool,
    pub bind_addr: SocketAddr,
    /// Per-IP sustained rate limit (requests per minute).
    pub rate_limit_rpm: u32,
    /// Per-IP burst capacity.
    pub rate_limit_burst: u32,
    /// Strategy for extracting client IP behind reverse proxies (defaults to `Direct`).
    pub proxy_ip_mode: ProxyIpMode,
    /// Optional override for Firebase App Check API base URL (useful for tests).
    pub firebase_api_base: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let creds_path = PathBuf::from(required_env("GOOGLE_APPLICATION_CREDENTIALS")?);
        let creds_raw = fs::read_to_string(&creds_path).with_context(|| {
            format!(
                "failed to read GOOGLE_APPLICATION_CREDENTIALS file at {}",
                creds_path.display()
            )
        })?;
        let service_account: ServiceAccountCredentials = serde_json::from_str(&creds_raw)
            .with_context(|| {
                format!(
                    "failed to parse service account JSON at {}",
                    creds_path.display()
                )
            })?;

        if service_account.client_email.trim().is_empty()
            || service_account.private_key.trim().is_empty()
        {
            bail!("service account JSON must contain non-empty client_email and private_key");
        }

        let firebase_project_number = required_env("FIREBASE_PROJECT_NUMBER")?;
        if !firebase_project_number.chars().all(|c| c.is_ascii_digit()) {
            bail!(
                "FIREBASE_PROJECT_NUMBER must be numeric, got '{}'",
                firebase_project_number
            );
        }

        let firebase_app_id = required_env("FIREBASE_APP_ID")?;
        let allowed_package_name = required_env("ALLOWED_PACKAGE_NAME")?;

        let raw_digests = required_env("ALLOWED_SIGNING_CERT_SHA256")?;
        let allowed_signing_cert_sha256 = parse_sha256_list(&raw_digests)?;

        let allow_grapheneos = match std::env::var("ALLOW_GRAPHENEOS") {
            Ok(v) => parse_bool(&v, "ALLOW_GRAPHENEOS")?,
            Err(_) => true,
        };

        let bind_addr_str =
            std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let bind_addr: SocketAddr = bind_addr_str
            .parse()
            .with_context(|| format!("invalid BIND_ADDR '{}'", bind_addr_str))?;

        let rate_limit_rpm: u32 = std::env::var("RATE_LIMIT_RPM")
            .ok()
            .map(|v| v.parse().context("invalid RATE_LIMIT_RPM"))
            .transpose()?
            .unwrap_or(60);

        let rate_limit_burst: u32 = std::env::var("RATE_LIMIT_BURST")
            .ok()
            .map(|v| v.parse().context("invalid RATE_LIMIT_BURST"))
            .transpose()?
            .unwrap_or(20);

        let trusted_hops: usize = std::env::var("TRUSTED_PROXY_HOPS")
            .ok()
            .map(|v| v.parse::<usize>().context("invalid TRUSTED_PROXY_HOPS"))
            .transpose()?
            .unwrap_or(1)
            .max(1);

        let proxy_ip_mode = match std::env::var("PROXY_IP_MODE") {
            Ok(v) => parse_proxy_ip_mode(&v, trusted_hops)?,
            Err(_) => match std::env::var("TRUST_PROXY_HEADERS") {
                Ok(v) => {
                    if parse_bool(&v, "TRUST_PROXY_HEADERS")? {
                        ProxyIpMode::Xff { trusted_hops }
                    } else {
                        ProxyIpMode::Direct
                    }
                }
                Err(_) => ProxyIpMode::Direct,
            },
        };

        let firebase_api_base = std::env::var("FIREBASE_API_BASE")
            .unwrap_or_else(|_| "https://firebaseappcheck.googleapis.com".to_string());

        Ok(Self {
            google_application_credentials: creds_path,
            service_account,
            firebase_project_number,
            firebase_app_id,
            allowed_package_name,
            allowed_signing_cert_sha256,
            allow_grapheneos,
            bind_addr,
            rate_limit_rpm,
            rate_limit_burst,
            proxy_ip_mode,
            firebase_api_base,
        })
    }
}

fn parse_proxy_ip_mode(val: &str, trusted_hops: usize) -> Result<ProxyIpMode> {
    match val.trim().to_ascii_lowercase().as_str() {
        "direct" | "none" => Ok(ProxyIpMode::Direct),
        "xff" => Ok(ProxyIpMode::Xff { trusted_hops }),
        "cloudflare" => Ok(ProxyIpMode::Cloudflare),
        other => bail!(
            "invalid PROXY_IP_MODE '{}' (expected 'direct', 'xff', or 'cloudflare')",
            other
        ),
    }
}

fn required_env(name: &str) -> Result<String> {
    let val = std::env::var(name)
        .with_context(|| format!("missing required environment variable {name}"))?;
    let trimmed = val.trim().to_string();
    if trimmed.is_empty() {
        bail!("environment variable {name} must not be empty");
    }
    Ok(trimmed)
}

fn parse_bool(val: &str, name: &str) -> Result<bool> {
    match val.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        other => bail!("invalid boolean value '{}' for {}", other, name),
    }
}

pub fn parse_sha256_list(raw: &str) -> Result<HashSet<String>> {
    let mut out = HashSet::new();
    for item in raw.split(',') {
        let normalized = item.trim().replace(':', "").to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "invalid SHA-256 hex digest '{}' in ALLOWED_SIGNING_CERT_SHA256 (expected 64 hex chars)",
                item.trim()
            );
        }
        out.insert(normalized);
    }
    if out.is_empty() {
        bail!("ALLOWED_SIGNING_CERT_SHA256 must contain at least one valid SHA-256 hex digest");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_sha256_digests() {
        let input = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99, \
                     0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let set = parse_sha256_list(input).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains("aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"));
        assert!(set.contains("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn rejects_invalid_sha256() {
        assert!(parse_sha256_list("deadbeef").is_err());
        assert!(parse_sha256_list("").is_err());
    }

    #[test]
    fn redacts_private_key_in_debug_output() {
        let creds = ServiceAccountCredentials {
            client_email: "attest@example.iam.gserviceaccount.com".into(),
            private_key: "-----BEGIN PRIVATE KEY-----\nSUPER_SECRET_MATERIAL\n-----END PRIVATE KEY-----".into(),
            private_key_id: Some("kid-1".into()),
            token_uri: default_token_uri(),
        };
        let rendered = format!("{creds:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("SUPER_SECRET_MATERIAL"));
    }

    #[test]
    fn parses_proxy_ip_modes() {
        assert_eq!(parse_proxy_ip_mode("direct", 1).unwrap(), ProxyIpMode::Direct);
        assert_eq!(parse_proxy_ip_mode("none", 1).unwrap(), ProxyIpMode::Direct);
        assert_eq!(
            parse_proxy_ip_mode("xff", 2).unwrap(),
            ProxyIpMode::Xff { trusted_hops: 2 }
        );
        assert_eq!(
            parse_proxy_ip_mode("cloudflare", 1).unwrap(),
            ProxyIpMode::Cloudflare
        );
        assert!(parse_proxy_ip_mode("invalid", 1).is_err());
    }
}
