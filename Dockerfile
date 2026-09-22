FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install uv for reproducible, uv.lock-pinned dependency installs
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1

# Install dependencies first (better layer caching), from the lockfile only
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project

# Copy the entire project and install it
COPY . .
RUN uv sync --frozen

# Expose port for dashboard
EXPOSE 8000

# Default command
CMD ["uv", "run", "python", "dashboard/app.py"]
