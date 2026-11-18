# The Cloudflare solver interloper's solver-backed providers use:
# github.com/B00H0O/cloudflare-solver (MIT, (c) 2026 B00H0), pinned commit.
#
# Its own Dockerfile installs Chrome for Testing "last known good" (158 as of
# 2026-11-18) while the solver presents a Chrome 138-148 User-Agent for
# Turnstile, so every /turnstile solve times out ("websocket read timed out").
# This is that Dockerfile with Chrome pinned to 148, contemporary with the
# commit, and the source fetched at the pinned commit, so it builds anywhere:
#
#   podman build -t il-solver deploy/solver
#   podman run -d --rm --name il-solver -p 127.0.0.1:4070:407 il-solver
#   INTERLOPER_SOLVER_URL=http://127.0.0.1:4070 interloper canary
FROM docker.io/alpine/git AS source
RUN git clone https://github.com/B00H0O/cloudflare-solver.git /src \
 && git -C /src checkout ce75d714925eef17f913ad6b4c16252bec090739

FROM docker.io/library/debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.80.0 --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /src
COPY --from=source /src/Cargo.toml /src/Cargo.lock ./
COPY --from=source /src/src ./src
RUN cargo build --release

FROM docker.io/library/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl unzip ca-certificates fonts-liberation \
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libxshmfence1 libx11-xcb1 libxkbcommon0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN set -eux; \
    curl -fL --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 30 -o /tmp/c.zip \
      https://storage.googleapis.com/chrome-for-testing-public/148.0.7778.178/linux64/chrome-linux64.zip; \
    unzip -q /tmp/c.zip -d /app; \
    mv /app/chrome-linux64 /app/chrome; \
    rm /tmp/c.zip

COPY --from=build /src/target/release/turnstile-solver /app/turnstile-solver
COPY --from=build /src/src/devices.json /app/src/devices.json

ENV CHROME_BIN=/app/chrome/chrome
EXPOSE 407
CMD ["/app/turnstile-solver"]
