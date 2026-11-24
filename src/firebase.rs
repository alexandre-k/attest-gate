use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::debug;

use crate::config::Config;
use crate::state::{now_unix_millis, now_unix_secs};

// Note: Google's Firebase App Check REST API (`firebaseappcheck.googleapis.com`) uses the
// standard GCP/Firebase OAuth2 scopes (`cloud-platform` / `firebase`); there is no standalone
// `.../auth/firebaseappcheck` scope (passing an unregistered scope URL to oauth2.googleapis.com
// causes Google to return an OIDC `id_token` instead of an OAuth2 `access_token`).
const OAUTH2_SCOPE_APPCHECK: &str = "https://www.googleapis.com/auth/cloud-platform";
const APPCHECK_EXCHANGE_AUD: &str =
    "https://firebaseappcheck.googleapis.com/google.firebase.appcheck.v1.TokenExchangeService";
const OAUTH2_CACHE_TTL: Duration = Duration::from_secs(50 * 60);
const CUSTOM_JWT_LIFETIME_SECS: u64 = 5 * 60;
const APP_CHECK_TOKEN_TTL: &str = "3600s";

#[derive(Debug, Clone)]
struct CachedBearerToken {
    access_token: String,
    expires_at: Instant,
}

#[derive(Debug, Clone, Serialize)]
pub struct MintedAppCheckToken {
    pub token: String,
    pub expire_time_millis: u64,
}

#[derive(Debug, Serialize)]
struct OAuth2AssertionClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct OAuth2TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Serialize)]
struct CustomAppCheckClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
    app_id: &'a str,
    ttl: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeCustomTokenRequest<'a> {
    custom_token: &'a str,
}

#[derive(Debug, Deserialize)]
struct ExchangeCustomTokenResponse {
    token: String,
    ttl: String,
}

/// Client for minting official Firebase App Check JWTs via Google's REST API,
/// caching the Service Account OAuth2 bearer token in memory for 50 minutes.
pub struct FirebaseClient {
    http: reqwest::Client,
    config: Arc<Config>,
    encoding_key: EncodingKey,
    bearer_cache: Mutex<Option<CachedBearerToken>>,
}

impl FirebaseClient {
    pub fn new(http: reqwest::Client, config: Arc<Config>) -> Result<Self> {
        let encoding_key = EncodingKey::from_rsa_pem(config.service_account.private_key.as_bytes())
            .context("failed to parse RSA private_key from service account JSON")?;

        Ok(Self {
            http,
            config,
            encoding_key,
            bearer_cache: Mutex::new(None),
        })
    }

    /// Exchanges a newly signed RS256 custom JWT for an official Firebase App Check token.
    pub async fn exchange_app_check_token(&self) -> Result<MintedAppCheckToken> {
        let bearer = self.get_or_refresh_bearer_token().await?;
        let custom_jwt = self.sign_custom_app_check_jwt()?;

        let url = format!(
            "{}/v1/projects/{}/apps/{}:exchangeCustomToken",
            self.config.firebase_api_base.trim_end_matches('/'),
            self.config.firebase_project_number,
            self.config.firebase_app_id
        );

        let req_body = ExchangeCustomTokenRequest {
            custom_token: &custom_jwt,
        };

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&bearer)
            .json(&req_body)
            .send()
            .await
            .context("HTTP POST to Firebase App Check exchangeCustomToken failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "Firebase App Check exchangeCustomToken failed with status {}: {}",
                status,
                body
            );
        }

        let body = resp
            .text()
            .await
            .context("failed to read Firebase App Check token response body")?;
        let exchanged: ExchangeCustomTokenResponse = serde_json::from_str(&body)
            .with_context(|| {
                format!(
                    "failed to deserialize Firebase App Check token response (keys/preview: {})",
                    safe_json_summary(&body)
                )
            })?;

        let ttl_millis = parse_protobuf_duration_millis(&exchanged.ttl).unwrap_or(3600 * 1000);
        let expire_time_millis = now_unix_millis().saturating_add(ttl_millis);

        Ok(MintedAppCheckToken {
            token: exchanged.token,
            expire_time_millis,
        })
    }

    /// Returns a cached Google OAuth2 access token (`firebaseappcheck` scope),
    /// refreshing it whenever it is absent or older than 50 minutes.
    async fn get_or_refresh_bearer_token(&self) -> Result<String> {
        let mut cache = self.bearer_cache.lock().await;
        let now = Instant::now();
        if let Some(cached) = cache.as_ref() {
            if now < cached.expires_at {
                return Ok(cached.access_token.clone());
            }
        }

        debug!("refreshing Google OAuth2 bearer token for firebaseappcheck scope");
        let assertion = self.sign_oauth2_assertion()?;

        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ];

        let resp = self
            .http
            .post(&self.config.service_account.token_uri)
            .form(&form)
            .send()
            .await
            .context("HTTP POST to Google OAuth2 token endpoint failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "Google OAuth2 token exchange failed with status {}: {}",
                status,
                body
            );
        }

        let body = resp
            .text()
            .await
            .context("failed to read Google OAuth2 token response body")?;
        let token_resp: OAuth2TokenResponse = serde_json::from_str(&body).with_context(|| {
            format!(
                "failed to parse Google OAuth2 token response (keys/preview: {})",
                safe_json_summary(&body)
            )
        })?;

        // Cache for 50 minutes (or less if Google returned an unusually short expires_in).
        let ttl = token_resp
            .expires_in
            .map(|secs| Duration::from_secs(secs.saturating_sub(600)).min(OAUTH2_CACHE_TTL))
            .unwrap_or(OAUTH2_CACHE_TTL);

        *cache = Some(CachedBearerToken {
            access_token: token_resp.access_token.clone(),
            expires_at: Instant::now() + ttl,
        });

        Ok(token_resp.access_token)
    }

    fn sign_oauth2_assertion(&self) -> Result<String> {
        let now = now_unix_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.config.service_account.private_key_id.clone();

        let claims = OAuth2AssertionClaims {
            iss: &self.config.service_account.client_email,
            scope: OAUTH2_SCOPE_APPCHECK,
            aud: &self.config.service_account.token_uri,
            iat: now,
            exp: now + 3600,
        };

        encode(&header, &claims, &self.encoding_key)
            .context("failed to sign Google OAuth2 RS256 assertion JWT")
    }

    /// Signs an RS256 custom token JWT targeting Firebase App Check's `TokenExchangeService`.
    /// Note: Google's `ExchangeCustomTokenRequest` proto takes `{"customToken": "..."}` while
    /// the desired `ttl` (`"3600s"`) is embedded as a signed claim inside the custom JWT.
    pub fn sign_custom_app_check_jwt(&self) -> Result<String> {
        let now = now_unix_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = self.config.service_account.private_key_id.clone();

        let claims = CustomAppCheckClaims {
            iss: &self.config.service_account.client_email,
            sub: &self.config.service_account.client_email,
            aud: APPCHECK_EXCHANGE_AUD,
            iat: now,
            exp: now + CUSTOM_JWT_LIFETIME_SECS,
            app_id: &self.config.firebase_app_id,
            ttl: APP_CHECK_TOKEN_TTL,
        };

        encode(&header, &claims, &self.encoding_key)
            .context("failed to sign Firebase App Check RS256 custom JWT")
    }
}

/// Parses a Google protobuf JSON Duration string like `"3600s"` or `"3599.5s"` into milliseconds.
pub fn parse_protobuf_duration_millis(duration_str: &str) -> Result<u64> {
    let trimmed = duration_str.trim();
    let secs_str = trimmed
        .strip_suffix('s')
        .with_context(|| format!("expected protobuf duration ending in 's', got '{trimmed}'"))?;
    let secs: f64 = secs_str
        .parse()
        .with_context(|| format!("invalid seconds value '{secs_str}'"))?;
    if !secs.is_finite() || secs < 0.0 {
        bail!("negative or non-finite duration '{trimmed}'");
    }
    Ok((secs * 1000.0).round() as u64)
}

/// Summarizes an upstream response body safely for error logs without leaking bearer/JWT secrets.
fn safe_json_summary(body: &str) -> String {
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(body) {
        let keys: Vec<&str> = map.keys().map(String::as_str).collect();
        return format!("json keys={keys:?}");
    }
    let trimmed = body.trim();
    let preview: String = trimmed.chars().take(120).collect();
    format!("non-object body len={} preview={preview:?}", trimmed.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_protobuf_duration_strings() {
        assert_eq!(parse_protobuf_duration_millis("3600s").unwrap(), 3_600_000);
        assert_eq!(
            parse_protobuf_duration_millis("3599.25s").unwrap(),
            3_599_250
        );
        assert!(parse_protobuf_duration_millis("3600").is_err());
        assert!(parse_protobuf_duration_millis("-10s").is_err());
    }
}
