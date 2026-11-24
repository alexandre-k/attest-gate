use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::RwLock;
use tower::ServiceExt;

use attest_gate::config::{Config, ProxyIpMode, ServiceAccountCredentials};
use attest_gate::firebase::FirebaseClient;
use attest_gate::rate_limit::IpRateLimiter;
use attest_gate::routes::build_router;
use attest_gate::state::{AppState, ChallengeStore, TrustAnchors, now_unix_secs};

fn generate_test_rsa_pems() -> (String, String) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let priv_pem = priv_key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let pub_pem = priv_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    (priv_pem, pub_pem)
}

fn make_test_state(priv_pem: String, burst: u32) -> (AppState, IpRateLimiter) {
    let mut digests = HashSet::new();
    digests.insert("a".repeat(64));

    let proxy_ip_mode = ProxyIpMode::Xff { trusted_hops: 1 };
    let config = Arc::new(Config {
        google_application_credentials: PathBuf::from("/tmp/test-sa.json"),
        service_account: ServiceAccountCredentials {
            client_email: "attest-gate@demo-project.iam.gserviceaccount.com".into(),
            private_key: priv_pem,
            private_key_id: Some("test-kid-1".into()),
            token_uri: "https://oauth2.googleapis.com/token".into(),
        },
        firebase_project_number: "123456789012".into(),
        firebase_app_id: "1:123456789012:android:abcdef123456".into(),
        allowed_package_name: "com.example.app".into(),
        allowed_signing_cert_sha256: digests,
        allow_grapheneos: true,
        bind_addr: "127.0.0.1:8080".parse::<SocketAddr>().unwrap(),
        rate_limit_rpm: 60,
        rate_limit_burst: burst,
        proxy_ip_mode,
        firebase_api_base: "https://firebaseappcheck.googleapis.com".into(),
    });

    let http = reqwest::Client::new();
    let firebase = Arc::new(FirebaseClient::new(http, config.clone()).unwrap());

    let now = now_unix_secs();
    let anchors = TrustAnchors {
        crl_last_synced_unix: Some(now),
        grapheneos_last_synced_unix: Some(now),
        grapheneos_timestamp: 1_776_709_772,
        ..Default::default()
    };

    let state = AppState {
        config,
        challenges: Arc::new(ChallengeStore::new()),
        trust_anchors: Arc::new(RwLock::new(anchors)),
        firebase,
    };

    let limiter = IpRateLimiter::new(60, burst, proxy_ip_mode);
    (state, limiter)
}

#[tokio::test]
async fn healthz_livez_and_challenge_endpoints_work() {
    let (priv_pem, _) = generate_test_rsa_pems();
    let (state, limiter) = make_test_state(priv_pem, 20);
    let app = build_router(state.clone(), limiter);

    // 0. GET /livez
    let resp = app
        .clone()
        .oneshot(Request::get("/livez").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 1. GET /healthz (ready -> 200 OK, no wildcard CORS, no sensitive internal fields)
    let resp = app
        .clone()
        .oneshot(
            Request::get("/healthz")
                .header("origin", "https://evil.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(!resp.headers().contains_key("access-control-allow-origin"));
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let health: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["google_crl"]["synced"], true);
    assert_eq!(health["grapheneos"]["synced"], true);
    assert!(health.get("active_challenges").is_none());
    assert!(health["google_crl"].get("last_error").is_none());

    // 2. POST /v1/challenge
    let resp = app
        .clone()
        .oneshot(
            Request::post("/v1/challenge")
                .header("x-forwarded-for", "203.0.113.10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let ch: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ch["expires_in"], 60);
    let nonce_b64 = ch["challenge"].as_str().unwrap();
    let decoded = URL_SAFE_NO_PAD.decode(nonce_b64).unwrap();
    assert_eq!(decoded.len(), 32);

    // 3. POST /v1/attest with unknown challenge -> 403 Forbidden with generic public message
    let attest_body = json!({
        "challenge": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "certificate_chain": ["AA==", "AA=="]
    });
    let resp = app
        .clone()
        .oneshot(
            Request::post("/v1/attest")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "203.0.113.10")
                .body(Body::from(attest_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let err_body = resp.into_body().collect().await.unwrap().to_bytes();
    let err_json: Value = serde_json::from_slice(&err_body).unwrap();
    assert_eq!(err_json["message"], "Attestation verification failed");

    // 4. GET /healthz returns 503 Service Unavailable when CRL is unsynced/stale (while /livez stays 200)
    state.trust_anchors.write().await.crl_last_synced_unix = None;
    let resp = app
        .clone()
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let live = app
        .oneshot(Request::get("/livez").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
}

#[tokio::test]
async fn rate_limiter_blocks_burst_excess_and_spoofed_xff_while_exempting_health_probes() {
    let (priv_pem, _) = generate_test_rsa_pems();
    let (state, limiter) = make_test_state(priv_pem, 2);
    let app = build_router(state, limiter);

    // Spoofed leftmost X-Forwarded-For values must NOT bypass the real rightmost client IP.
    for fake_ip in ["1.1.1.1", "2.2.2.2"] {
        let resp = app
            .clone()
            .oneshot(
                Request::post("/v1/challenge")
                    .header("x-forwarded-for", format!("{fake_ip}, 198.51.100.5"))
                    .header("cf-connecting-ip", fake_ip)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 3rd request with yet another spoofed leftmost IP still hits 198.51.100.5's burst limit -> 429.
    let resp = app
        .clone()
        .oneshot(
            Request::post("/v1/challenge")
                .header("x-forwarded-for", "3.3.3.3, 198.51.100.5")
                .header("cf-connecting-ip", "3.3.3.3")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"));

    // /healthz and /livez remain exempt from rate limiting for k3s probes.
    let health = app
        .clone()
        .oneshot(
            Request::get("/healthz")
                .header("x-forwarded-for", "198.51.100.5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);

    let live = app
        .oneshot(
            Request::get("/livez")
                .header("x-forwarded-for", "198.51.100.5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
}

#[test]
fn firebase_custom_jwt_signs_rs256_with_expected_claims() {
    #[derive(Debug, Deserialize)]
    struct Claims {
        iss: String,
        sub: String,
        aud: String,
        iat: u64,
        exp: u64,
        app_id: String,
        ttl: String,
    }

    let (priv_pem, pub_pem) = generate_test_rsa_pems();
    let (state, _) = make_test_state(priv_pem, 20);
    let jwt = state.firebase.sign_custom_app_check_jwt().unwrap();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[
        "https://firebaseappcheck.googleapis.com/google.firebase.appcheck.v1.TokenExchangeService",
    ]);

    let decoded = decode::<Claims>(
        &jwt,
        &DecodingKey::from_rsa_pem(pub_pem.as_bytes()).unwrap(),
        &validation,
    )
    .unwrap();

    assert_eq!(decoded.header.kid.as_deref(), Some("test-kid-1"));
    assert_eq!(
        decoded.claims.iss,
        "attest-gate@demo-project.iam.gserviceaccount.com"
    );
    assert_eq!(decoded.claims.sub, decoded.claims.iss);
    assert_eq!(
        decoded.claims.aud,
        "https://firebaseappcheck.googleapis.com/google.firebase.appcheck.v1.TokenExchangeService"
    );
    assert_eq!(decoded.claims.app_id, "1:123456789012:android:abcdef123456");
    assert_eq!(decoded.claims.ttl, "3600s");
    assert_eq!(decoded.claims.exp - decoded.claims.iat, 300);

    // Silence unused import warning if any.
    let _ = IpAddr::V4(Ipv4Addr::LOCALHOST);
}
