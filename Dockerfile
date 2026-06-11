# §15 — alpine base, static binary at /usr/local/bin/pyfusa
FROM python:3.12-alpine AS builder
WORKDIR /build
COPY . .
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-alpine
LABEL org.opencontainers.image.title="py-FuSa" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.source="https://github.com/SoundMatt/py-FuSa" \
      org.opencontainers.image.licenses="MPL-2.0" \
      io.x-fusa.tool="py-FuSa" \
      io.x-fusa.language="python" \
      io.x-fusa.binary="pyfusa" \
      io.x-fusa.spec-version="1.9"

COPY --from=builder /install /usr/local
WORKDIR /project
ENTRYPOINT ["pyfusa"]
CMD ["help"]
