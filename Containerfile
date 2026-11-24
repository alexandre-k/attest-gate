# syntax=docker/dockerfile:1
# Multi-stage Containerfile (Podman & Docker compatible)

# ---- Stage 1: Builder ----
FROM docker.io/library/rust:1-bookworm AS builder

WORKDIR /build

# Cache dependencies separately from application source
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src \
    && echo "pub fn _dummy() {}" > src/lib.rs \
    && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked 2>/dev/null || cargo build --release \
    && rm -rf src

# Build the actual attest-gate binary
COPY src ./src
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --locked --bin attest-gate

# ---- Stage 2: Distroless Runtime (non-root UID 65532) ----
FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /build/target/release/attest-gate /usr/local/bin/attest-gate

ENV BIND_ADDR=0.0.0.0:8080 \
    ALLOW_GRAPHENEOS=true \
    RUST_LOG=attest_gate=info,tower_http=info

EXPOSE 8080

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/attest-gate"]
