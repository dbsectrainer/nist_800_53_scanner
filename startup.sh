#!/bin/bash
set -e

echo "Starting NIST 800-53 Compliance Scanner Setup..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip first to avoid resolver warnings
echo "Upgrading pip..."
pip install --upgrade pip --quiet

# Install all required dependencies (scanner + dashboard)
echo "Installing dependencies..."
pip install -r requirements.txt
pip install flask flask-cors plotly pandas numpy pyyaml validators psutil \
    pywinrm azure-identity azure-mgmt-security google-cloud-iam \
    paramiko aiokafka authlib aiofiles kubernetes flower \
    opentelemetry-instrumentation-fastapi aws-lambda-powertools \
    google-cloud-functions

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "Warning: Docker is not running. Skipping Docker services."
else
    # Start only the infrastructure services (skip the scanner image build)
    echo "Starting Docker services (Redis, Jaeger, Prometheus, Grafana)..."
    docker-compose up -d redis jaeger prometheus grafana || true

    # Wait for services to be ready
    echo "Waiting for services to be ready..."
    sleep 10
fi

# Start the main scanner in the background (requires --config argument)
echo "Starting NIST compliance scanner..."
python3 scan.py --config config.yaml &
SCANNER_PID=$!
echo "Scanner started with PID $SCANNER_PID"

# Start the dashboard application
echo "Starting web dashboard..."
python3 dashboard/app.py

# Note: When stopping, you'll need to:
# 1. Stop the Flask server (Ctrl+C)
# 2. Kill the background scanner: kill $SCANNER_PID
# 3. Run 'docker-compose down' to stop Docker services
