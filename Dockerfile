# APILeak OWASP Enhancement Dockerfile
# Enterprise-grade API fuzzing and OWASP testing tool
# Optimized for size (<200MB) and security (non-root execution)

FROM python:3.11-slim-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    && rm -rf /var/cache/apk/*

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --user -r /tmp/requirements.txt

# Production stage
FROM python:3.11-slim-alpine

# Metadata
LABEL maintainer="FortGenix Team <team@apileak.com>" \
      description="Enterprise-grade API fuzzing and OWASP testing tool" \
      version="0.1.0" \
      org.opencontainers.image.title="APILeak" \
      org.opencontainers.image.description="OWASP API Security Top 10 testing tool" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.vendor="FortGenix Team" \
      org.opencontainers.image.licenses="MIT"

# Install runtime dependencies only
RUN apk add --no-cache \
    ca-certificates \
    && rm -rf /var/cache/apk/* \
    && update-ca-certificates

# Create non-root user for security (Requirements 13.2)
RUN addgroup -g 1000 apileak && \
    adduser -D -s /bin/sh -u 1000 -G apileak apileak

# Set working directory
WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/apileak/.local

# Copy application code with proper ownership
COPY --chown=apileak:apileak core/ ./core/
COPY --chown=apileak:apileak modules/ ./modules/
COPY --chown=apileak:apileak utils/ ./utils/
COPY --chown=apileak:apileak templates/ ./templates/
COPY --chown=apileak:apileak wordlists/ ./wordlists/
COPY --chown=apileak:apileak config/ ./config/
COPY --chown=apileak:apileak apileaks.py .
COPY --chown=apileak:apileak setup.py .
COPY --chown=apileak:apileak README.md .

# Create directories for reports and logs with proper permissions
RUN mkdir -p /app/reports /app/logs /app/output && \
    chown -R apileak:apileak /app/reports /app/logs /app/output

# Switch to non-root user (Requirements 13.2)
USER apileak

# Add local Python packages to PATH
ENV PATH="/home/apileak/.local/bin:$PATH"

# Environment variables for configuration (Requirements 13.3)
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    APILEAK_LOG_LEVEL=INFO \
    APILEAK_CONFIG_FILE="" \
    APILEAK_TARGET="" \
    APILEAK_OUTPUT_FILE="" \
    APILEAK_RATE_LIMIT="10" \
    APILEAK_MODULES="" \
    APILEAK_JWT_TOKEN="" \
    APILEAK_USER_AGENT="" \
    APILEAK_TIMEOUT="10" \
    APILEAK_MAX_DEPTH="3" \
    APILEAK_VERIFY_SSL="true"

# Health check endpoint (Requirements 13.4)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; from core import APILeakCore; print('APILeak container healthy'); sys.exit(0)" || exit 1

# Create entrypoint script for environment variable support
COPY --chown=apileak:apileak <<'EOF' /app/entrypoint.sh
#!/bin/sh
set -e

# Build command line arguments from environment variables
ARGS=""

# Add config file if specified
if [ -n "$APILEAK_CONFIG_FILE" ]; then
    ARGS="$ARGS --config $APILEAK_CONFIG_FILE"
fi

# Add target if specified
if [ -n "$APILEAK_TARGET" ]; then
    ARGS="$ARGS --target $APILEAK_TARGET"
fi

# Add output filename (not directory, as that's handled by the app)
if [ -n "$APILEAK_OUTPUT_FILE" ]; then
    ARGS="$ARGS --output $APILEAK_OUTPUT_FILE"
fi

# Add rate limit
if [ -n "$APILEAK_RATE_LIMIT" ]; then
    ARGS="$ARGS --rate-limit $APILEAK_RATE_LIMIT"
fi

# Add modules
if [ -n "$APILEAK_MODULES" ]; then
    ARGS="$ARGS --modules $APILEAK_MODULES"
fi

# Add JWT token
if [ -n "$APILEAK_JWT_TOKEN" ]; then
    ARGS="$ARGS --jwt $APILEAK_JWT_TOKEN"
fi

# Add user agent
if [ -n "$APILEAK_USER_AGENT" ]; then
    ARGS="$ARGS --user-agent-custom $APILEAK_USER_AGENT"
fi

# Add log level
ARGS="$ARGS --log-level $APILEAK_LOG_LEVEL"

# Execute APILeak with constructed arguments
if [ $# -eq 0 ]; then
    # No arguments provided, show help
    exec python apileaks.py --help
else
    # Execute with provided command and constructed arguments
    exec python apileaks.py "$@" $ARGS
fi
EOF

RUN chmod +x /app/entrypoint.sh

# Default entrypoint and command
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["full"]

# Expose volume mounts (Requirements 13.3)
VOLUME ["/app/config", "/app/reports", "/app/logs", "/app/wordlists"]

# Multi-architecture support (Requirements 13.5)
# This Dockerfile supports both amd64 and arm64 architectures