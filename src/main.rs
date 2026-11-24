use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

use attest_gate::config::Config;
use attest_gate::firebase::FirebaseClient;
use attest_gate::rate_limit::IpRateLimiter;
use attest_gate::roots::GOOGLE_HARDWARE_ROOT_SPKIS;
use attest_gate::routes::build_router;
use attest_gate::state::{AppState, ChallengeStore, TrustAnchors};
use attest_gate::sync::start_sync_worker;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let config = Arc::new(Config::from_env().context("failed to load configuration")?);

    // Force eager initialization and self-verification of pinned Google hardware root SPKIs.
    info!(
        pinned_roots = GOOGLE_HARDWARE_ROOT_SPKIS.len(),
        package = %config.allowed_package_name,
        allow_grapheneos = config.allow_grapheneos,
        "loaded pinned Google Android hardware attestation roots"
    );

    let http = reqwest::Client::builder()
        .user_agent(concat!("attest-gate/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .use_rustls_tls()
        .build()
        .context("failed to build reqwest HTTP client")?;

    let firebase = Arc::new(FirebaseClient::new(http.clone(), config.clone())?);
    let challenges = Arc::new(ChallengeStore::new());
    let trust_anchors = Arc::new(RwLock::new(TrustAnchors::default()));
    let rate_limiter = IpRateLimiter::new(
        config.rate_limit_rpm,
        config.rate_limit_burst,
        config.proxy_ip_mode,
    );

    // Start Google CRL & GrapheneOS trust-anchor sync worker (startup + every 6 hours).
    start_sync_worker(http, trust_anchors.clone(), config.allow_grapheneos).await;

    // Periodically evict expired challenges and stale rate-limiter buckets to keep RAM tiny.
    {
        let challenges = challenges.clone();
        let rate_limiter = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let expired = challenges.evict_expired();
                let stale_ips = rate_limiter.evict_stale(Duration::from_secs(5 * 60));
                if expired > 0 || stale_ips > 0 {
                    debug!(expired, stale_ips, "reaped expired challenges and stale IP buckets");
                }
            }
        });
    }

    let state = AppState {
        config: config.clone(),
        challenges,
        trust_anchors,
        firebase,
    };

    let app = build_router(state, rate_limiter);
    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("failed to bind TCP listener on {}", config.bind_addr))?;

    info!(addr = %config.bind_addr, "attest-gate listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("HTTP server exited with error")?;

    info!("attest-gate shut down cleanly");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("attest_gate=info,tower_http=info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
