FROM python:3.12-slim

LABEL maintainer="Your Name <you@example.com>"
LABEL description="BugBounty MCP Server"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    build-essential \
    golang-go \
    default-jdk \
    && rm -rf /var/lib/apt/lists/*

# Install ProjectDiscovery tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install github.com/projectdiscovery/nuclei/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/projectdiscovery/gau/cmd/gau@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/ffuf/ffuf@latest

# Install other security tools
RUN pip install nuclei-templates || true

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"

# Copy application
COPY src/ ./src/
COPY config/ ./config/

# Create directories
RUN mkdir -p /app/output /tmp/bugbounty_mcp

# Set environment
ENV PYTHONPATH=/app
ENV PATH="/root/go/bin:${PATH}"

# Expose port
EXPOSE 8765

# Run server
CMD ["python", "-m", "bugbounty_mcp.server"]
