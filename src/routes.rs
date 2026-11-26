use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router, middleware};
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::attestation::verify_attestation;
use crate::error::AppError;
use crate::rate_limit::{IpRateLimiter, rate_limit_middleware};
use crate::state::{AppState, SyncComponentStatus, now_unix_secs};

const MAX_ATTEST_BODY_BYTES: usize = 64 * 1024; // 64 KiB

#[derive(Debug, Serialize)]
pub struct LiveResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub google_crl: SyncComponentStatus,
    pub grapheneos: SyncComponentStatus,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub expires_in: u64,
}

#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    pub challenge: String,
    pub certificate_chain: Vec<String>,
    /// When `true`, requests a single-use limited-use App Check token (`"limitedUse": true`)
    /// for replay-protected endpoints such as Firebase AI Logic.
    /// Defaults to `false` (standard session token required by Cloud Firestore, Storage, etc.).
    #[serde(default, alias = "limitedUse")]
    pub limited_use: bool,
}

#[derive(Debug, Serialize)]
pub struct AttestResponse {
    pub token: String,
    pub expire_time_millis: u64,
}

pub fn build_router(state: AppState, rate_limiter: IpRateLimiter) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/healthz", get(healthz))
        .route("/v1/challenge", post(issue_challenge))
        .route("/v1/attest", post(attest))
        .layer(DefaultBodyLimit::max(MAX_ATTEST_BODY_BYTES))
        .layer(middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn livez() -> Json<LiveResponse> {
    Json(LiveResponse { status: "ok" })
}

async fn healthz(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let now = now_unix_secs();
    let anchors = state.trust_anchors.read().await;
    let google_crl = anchors.crl_status(now);
    let grapheneos = anchors.grapheneos_status();
    let ready = anchors.is_crl_fresh(now) && (!state.config.allow_grapheneos || grapheneos.synced);

    let status_code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status_code,
        Json(HealthResponse {
            status: if ready { "ok" } else { "degraded" },
            google_crl,
            grapheneos,
        }),
    )
}

async fn issue_challenge(
    State(state): State<AppState>,
) -> Result<Json<ChallengeResponse>, AppError> {
    let (challenge, expires_in) = state.challenges.issue().ok_or_else(|| {
        AppError::ServiceUnavailable("challenge store at capacity; please retry shortly".into())
    })?;
    Ok(Json(ChallengeResponse {
        challenge,
        expires_in,
    }))
}

async fn attest(
    State(state): State<AppState>,
    Json(payload): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, AppError> {
    if payload.challenge.trim().is_empty() {
        return Err(AppError::BadRequest("challenge must not be empty".into()));
    }

    let verified = {
        let anchors = state.trust_anchors.read().await;
        verify_attestation(
            payload.challenge.trim(),
            &payload.certificate_chain,
            &state.challenges,
            &anchors,
            &state.config,
        )?
    };

    info!(
        root = %verified.root_name,
        security_level = ?verified.security_level,
        boot_state = ?verified.verified_boot_state,
        package = %verified.package_name,
        limited_use = payload.limited_use,
        "hardware key attestation verified; exchanging Firebase App Check token"
    );

    let minted = state
        .firebase
        .exchange_app_check_token(payload.limited_use)
        .await
        .map_err(|err| AppError::Upstream(format!("{err:#}")))?;

    Ok(Json(AttestResponse {
        token: minted.token,
        expire_time_millis: minted.expire_time_millis,
    }))
}
