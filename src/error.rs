use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;
use tracing::warn;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("attestation rejected: {0}")]
    Forbidden(String),

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("trust anchors not yet synchronized: {0}")]
    ServiceUnavailable(String),

    #[error("upstream Firebase App Check error: {0}")]
    Upstream(String),

    #[error("internal server error: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, public_message) = match &self {
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            AppError::Forbidden(msg) => {
                warn!(reason = %msg, "attestation rejected");
                (
                    StatusCode::FORBIDDEN,
                    "attestation_failed",
                    "Attestation verification failed".to_string(),
                )
            }
            AppError::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests. Please retry later.".to_string(),
            ),
            AppError::ServiceUnavailable(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                msg.clone(),
            ),
            AppError::Upstream(msg) => {
                tracing::error!(error = %msg, "upstream Firebase API error");
                (
                    StatusCode::BAD_GATEWAY,
                    "upstream_error",
                    "Failed to exchange attestation for Firebase App Check token".to_string(),
                )
            }
            AppError::Internal(msg) => {
                tracing::error!(error = %msg, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Internal server error".to_string(),
                )
            }
        };

        (
            status,
            Json(ErrorBody {
                error: code,
                message: public_message,
            }),
        )
            .into_response()
    }
}
