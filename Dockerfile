# syntax=docker/dockerfile:1.7

# ---- build stage ------------------------------------------------------------
# Build a statically linked musl binary so the runtime stage needs neither
# glibc nor OpenSSL/libssl3.
FROM rust:1-alpine AS build
WORKDIR /src
# `ring`, `zstd-sys` and `mimalloc` need a C toolchain and musl headers.
RUN apk add --no-cache build-base pkgconfig linux-headers
COPY . .
# Cache mounts keep incremental rebuilds fast without bloating the image.
# Passing `--target` explicitly keeps `RUSTFLAGS` off proc-macro crates.
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    ARCH="$(uname -m)-unknown-linux-musl" \
 && cargo build --release --locked --target "$ARCH" -p velox-cli --bin velox \
 && install -Dm755 "target/$ARCH/release/velox" /out/velox

# ---- runtime stage ----------------------------------------------------------
# distroless/static: CA certs + tzdata + nonroot user (uid 65532); no libc,
# no OpenSSL, no shell, no package manager (0 OS-package CVEs).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/velox /usr/local/bin/velox
COPY docker/velox.toml /etc/velox/velox.toml
# 8080/tcp  HTTP/1.1        8443/tcp  HTTPS (h2, http/1.1)
# 8443/udp  HTTP/3 (QUIC)   (the admin API is loopback-only by design)
EXPOSE 8080/tcp 8443/tcp 8443/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/velox"]
CMD ["start", "-c", "/etc/velox/velox.toml"]
