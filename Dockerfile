# Stage 1: Build wheel
FROM python:3.12-slim AS builder

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir build && \
    python -m build --wheel

# Stage 2: Runtime
FROM python:3.12-slim

LABEL org.opencontainers.image.title="unravel-sbom" \
      org.opencontainers.image.description="Standards-compliant SBOM generator supporting SPDX 3.0.1 (BSI TR-03183-2) and CycloneDX 1.6" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

WORKDIR /scan

ENTRYPOINT ["unravel-sbom"]
CMD ["--help"]
