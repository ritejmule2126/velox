# syntax=docker/dockerfile:1.7

# ---- build stage ------------------------------------------------------------
FROM rust:1-slim-bookworm AS build
WORKDIR /src
# `ring` needs a C compiler; everything else is pure Rust.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config \
 && rm -rf /var/lib/apt/lists/*
COPY . .
# Cache mounts keep incremental rebuilds fast without bloating the image.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p velox-cli --bin velox \
 && install -D target/release/velox /out/velox

# ---- runtime stage ----------------------------------------------------------
# distroless/cc: glibc + libgcc only; no shell, no package manager, runs as
# the unprivileged `nonroot` user (uid 65532).
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/velox /usr/local/bin/velox
COPY docker/velox.toml /etc/velox/velox.toml
# 8080/tcp  HTTP/1.1        8443/tcp  HTTPS (h2, http/1.1)
# 8443/udp  HTTP/3 (QUIC)   (the admin API is loopback-only by design)
EXPOSE 8080/tcp 8443/tcp 8443/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/velox"]
CMD ["start", "-c", "/etc/velox/velox.toml"]
