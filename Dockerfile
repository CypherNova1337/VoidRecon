# VoidRecon — all-in-one image: the framework plus the best-in-class binaries it
# orchestrates, so the hybrid fast-path is always hot.
#
#   docker build -t voidrecon .
#   docker run --rm -it -v "$PWD/runs:/runs" voidrecon run example.com
#
# ── Stage 1: build the Go tooling ────────────────────────────────────────────
FROM golang:1.22-bookworm AS gotools
ENV GOBIN=/out CGO_ENABLED=0
RUN mkdir -p /out && \
    go install github.com/CypherNova1337/dns-helix@latest && \
    go install github.com/CypherNova1337/paramvoid@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest

# ── Stage 2: VoidRecon runtime ───────────────────────────────────────────────
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers \
    VOIDRECON_GENERAL_OUTPUT_DIR=/runs

# Runtime deps: openssl (TLS), whois, ca-certs.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates openssl whois curl \
    && rm -rf /var/lib/apt/lists/*

# Go tools from stage 1.
COPY --from=gotools /out/ /usr/local/bin/

WORKDIR /opt/voidrecon
COPY . .

# Install VoidRecon + optional extras, then the headless browser it drives.
RUN pip install ".[full,screenshots]" && \
    python -m playwright install --with-deps chromium

WORKDIR /runs
ENTRYPOINT ["voidrecon"]
CMD ["--help"]
