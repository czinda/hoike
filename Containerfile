# hoike — multi-stage container build
#
# Build:  podman build -f Containerfile -t hoike .
# Run:    podman run -p 2560:2560 -v ./hoike.toml:/etc/hoike/hoike.toml:ro hoike serve --config /etc/hoike/hoike.toml

# ── Stage 1: Build ──────────────────────────────
FROM docker.io/library/rust:1.97-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --release \
    && strip target/release/hoike target/release/ahu

# ── Stage 2: Runtime ────────────────────────────
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /build/target/release/hoike /usr/local/bin/hoike
COPY --from=builder /build/target/release/ahu /usr/local/bin/ahu

EXPOSE 2560

ENTRYPOINT ["hoike"]
CMD ["serve", "--config", "/etc/hoike/hoike.toml"]
