use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;

use crate::config::ProxyIpMode;
use crate::error::AppError;

pub const DEFAULT_MAX_BUCKETS: usize = 50_000;
const OVERFLOW_RETRY_AFTER_SECS: u64 = 10;

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

/// Lock-free per-IP token-bucket rate limiter backed by a bounded `DashMap`.
#[derive(Clone)]
pub struct IpRateLimiter {
    buckets: Arc<DashMap<IpAddr, Bucket>>,
    refill_per_sec: f64,
    burst: f64,
    proxy_ip_mode: ProxyIpMode,
    max_entries: usize,
}

impl IpRateLimiter {
    pub fn new(requests_per_minute: u32, burst: u32, proxy_ip_mode: ProxyIpMode) -> Self {
        Self::with_max_entries(
            requests_per_minute,
            burst,
            proxy_ip_mode,
            DEFAULT_MAX_BUCKETS,
        )
    }

    pub fn with_max_entries(
        requests_per_minute: u32,
        burst: u32,
        proxy_ip_mode: ProxyIpMode,
        max_entries: usize,
    ) -> Self {
        let rpm = requests_per_minute.max(1) as f64;
        let burst = burst.max(1) as f64;
        Self {
            buckets: Arc::new(DashMap::new()),
            refill_per_sec: rpm / 60.0,
            burst,
            proxy_ip_mode,
            max_entries: max_entries.max(1),
        }
    }

    /// Attempts to consume 1 token for `ip`. Returns `Ok(())` or `Err(retry_after_secs)`.
    pub fn check(&self, ip: IpAddr) -> Result<(), u64> {
        let now = Instant::now();

        if let Some(mut entry) = self.buckets.get_mut(&ip) {
            return self.consume_from_bucket(&mut entry, now);
        }

        // Prevent unbounded memory growth under spoofed-IP / IPv6-rotation floods.
        if self.buckets.len() >= self.max_entries {
            self.evict_stale(Duration::from_secs(60));
            if self.buckets.len() >= self.max_entries {
                return Err(OVERFLOW_RETRY_AFTER_SECS);
            }
        }

        let mut entry = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: self.burst,
            last_refill: now,
        });
        self.consume_from_bucket(&mut entry, now)
    }

    fn consume_from_bucket(&self, bucket: &mut Bucket, now: Instant) -> Result<(), u64> {
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.burst);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let needed = 1.0 - bucket.tokens;
            let retry_after = (needed / self.refill_per_sec).ceil().max(1.0) as u64;
            Err(retry_after)
        }
    }

    /// Evicts buckets idle for longer than `max_idle` to prevent unbounded memory growth.
    pub fn evict_stale(&self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let before = self.buckets.len();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_refill) < max_idle);
        before.saturating_sub(self.buckets.len())
    }
}

/// Axum middleware enforcing per-IP rate limiting (exempting `/healthz` and `/livez`).
pub async fn rate_limit_middleware(
    State(limiter): State<IpRateLimiter>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path == "/healthz" || path == "/livez" {
        return next.run(request).await;
    }

    // Fail closed into a shared fallback bucket if no client IP can be resolved.
    let client_ip = extract_client_ip(&request, limiter.proxy_ip_mode)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    if let Err(retry_after) = limiter.check(client_ip) {
        let mut resp = AppError::RateLimited.into_response();
        *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
        if let Ok(val) = HeaderValue::from_str(&retry_after.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, val);
        }
        return resp;
    }

    next.run(request).await
}

fn extract_rightmost_xff(request: &Request, trusted_hops: usize) -> Option<IpAddr> {
    let xff = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())?;

    let ips: Vec<IpAddr> = xff
        .split(',')
        .filter_map(|part| part.trim().parse::<IpAddr>().ok())
        .collect();

    if ips.is_empty() {
        return None;
    }

    // Reverse proxies append the true peer IP on the right; taking the rightmost untrusted hop
    // prevents clients from bypassing rate limiting by prepending spoofed X-Forwarded-For entries.
    let hops = trusted_hops.max(1);
    let idx = ips.len().saturating_sub(hops);
    ips.get(idx).copied()
}

fn extract_client_ip(request: &Request, mode: ProxyIpMode) -> Option<IpAddr> {
    match mode {
        ProxyIpMode::Direct => {}
        ProxyIpMode::Xff { trusted_hops } => {
            if let Some(ip) = extract_rightmost_xff(request, trusted_hops) {
                return Some(ip);
            }
            if let Some(xri) = request
                .headers()
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
            {
                if let Ok(ip) = xri.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
        ProxyIpMode::Cloudflare => {
            if let Some(cf_ip) = request
                .headers()
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
            {
                if let Ok(ip) = cf_ip.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
            if let Some(ip) = extract_rightmost_xff(request, 1) {
                return Some(ip);
            }
        }
    }

    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn enforces_burst_and_allows_independent_ips() {
        let limiter = IpRateLimiter::new(60, 2, ProxyIpMode::Direct);
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(limiter.check(ip_a).is_ok());
        assert!(limiter.check(ip_a).is_ok());
        assert!(limiter.check(ip_a).is_err());

        // Independent IP still has full burst.
        assert!(limiter.check(ip_b).is_ok());
    }

    #[test]
    fn caps_bucket_map_to_prevent_oom() {
        let limiter = IpRateLimiter::with_max_entries(60, 5, ProxyIpMode::Direct, 2);
        let ip_1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip_3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        assert!(limiter.check(ip_1).is_ok());
        assert!(limiter.check(ip_2).is_ok());
        // New IP rejected when map is full; existing IPs still work.
        assert!(limiter.check(ip_3).is_err());
        assert!(limiter.check(ip_1).is_ok());
    }

    #[test]
    fn xff_mode_uses_rightmost_hop_and_ignores_spoofed_leftmost_and_cf_header() {
        let req = Request::builder()
            .uri("/v1/challenge")
            .header("cf-connecting-ip", "192.0.2.99")
            .header("x-forwarded-for", "1.1.1.1, 2.2.2.2, 198.51.100.7")
            .body(Body::empty())
            .unwrap();

        assert_eq!(
            extract_client_ip(&req, ProxyIpMode::Xff { trusted_hops: 1 }),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
        assert_eq!(
            extract_client_ip(&req, ProxyIpMode::Xff { trusted_hops: 2 }),
            Some(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)))
        );
        assert_eq!(extract_client_ip(&req, ProxyIpMode::Direct), None);
        assert_eq!(
            extract_client_ip(&req, ProxyIpMode::Cloudflare),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)))
        );
    }
}
