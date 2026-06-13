# syntax=docker/dockerfile:1
#
# Multi-stage build for py-FuSa.
# Stage 1 installs pyfusa into a prefix; Stage 2 is the minimal runtime image.
#
# Build:
#   docker build -t py-fusa .
#
# Run (mount your project at /project):
#   docker run --rm -v "$(pwd)":/project py-fusa check
#   docker run --rm -v "$(pwd)":/project py-fusa trace
#   docker run --rm -v "$(pwd)":/project py-fusa release
#   docker run --rm -v "$(pwd)":/project py-fusa qualify

# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM python:3.12-alpine AS builder

WORKDIR /build

# Copy dependency manifest first for layer-cache efficiency.
COPY pyproject.toml ./
COPY pyfusa/ ./pyfusa/
COPY README.md ./

RUN pip install --no-cache-dir --prefix=/install .

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-alpine

# git for provenance VCS info; ca-certificates for TLS (vuln scan OSV API).
RUN apk add --no-cache git ca-certificates

COPY --from=builder /install /usr/local

LABEL org.opencontainers.image.title="py-FuSa" \
      org.opencontainers.image.description="Functional safety enablement toolkit for Python" \
      org.opencontainers.image.version="0.1.7" \
      org.opencontainers.image.source="https://github.com/SoundMatt/py-FuSa" \
      org.opencontainers.image.licenses="MPL-2.0" \
      io.x-fusa.tool="py-FuSa" \
      io.x-fusa.language="python" \
      io.x-fusa.binary="pyfusa" \
      io.x-fusa.spec-version="1.10.8"

WORKDIR /project

ENTRYPOINT ["pyfusa"]
CMD ["help"]
