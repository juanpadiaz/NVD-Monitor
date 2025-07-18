# Multi-stage build for NVD Monitor
FROM python:3.10-slim-bullseye as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    pkg-config \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Production stage
FROM python:3.10-slim-bullseye

# Create non-root user
RUN groupadd -r nvdmonitor && useradd -r -g nvdmonitor nvdmonitor

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    default-mysql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create application directories
RUN mkdir -p /opt/nvd-monitor /var/log/nvd-monitor /var/lib/nvd-monitor && \
    chown -R nvdmonitor:nvdmonitor /opt/nvd-monitor /var/log/nvd-monitor /var/lib/nvd-monitor

# Copy application files
COPY --chown=nvdmonitor:nvdmonitor src/ /opt/nvd-monitor/
COPY --chown=nvdmonitor:nvdmonitor docker/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

# Switch to non-root user
USER nvdmonitor

# Set working directory
WORKDIR /opt/nvd-monitor

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python nvd_monitor.py --test-db || exit 1

# Expose port for future web interface
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--daemon"]
