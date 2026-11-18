# One static-ish binary: `interloper serve` is the HTTP API, every other
# subcommand works too (`docker run --rm interloper canary`).
#
# BoringSSL (wreq's TLS, which is what gives requests a real Chrome
# fingerprint) builds from source, hence cmake, clang and perl in the builder.
FROM docker.io/library/rust:1-bookworm AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang libclang-dev perl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p interloper-cli \
 && cp target/release/interloper /usr/local/bin/interloper

FROM docker.io/library/debian:bookworm-slim
# curl only for the HEALTHCHECK; ca-certificates for every provider call.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1000 app
COPY --from=build /usr/local/bin/interloper /usr/local/bin/interloper
USER app
# Health and the SQLite address store live under the app user's home, so a
# volume on /home/app/.local/state keeps both across restarts.
ENV XDG_STATE_HOME=/home/app/.local/state \
    INTERLOPER_DATABASE=/home/app/.local/state/interloper/addresses.db \
    PORT=8000
EXPOSE 8000
# (podman: build with `--format docker`, or OCI drops HEALTHCHECK.)
# /health needs no key and is exempt from the rate limiter, so probing it
# cannot spend a real caller's budget.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["sh", "-c", "curl -fsS http://127.0.0.1:$PORT/health >/dev/null"]
# exec form: interloper is PID 1 and gets the platform's SIGTERM directly,
# which triggers a graceful shutdown that saves health.
ENTRYPOINT ["interloper"]
CMD ["serve"]
