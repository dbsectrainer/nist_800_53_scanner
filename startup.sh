#!/bin/bash

echo "Starting NIST 800-53 Compliance Scanner Setup..."

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install required dependencies
echo "Installing dependencies..."
pip install -r requirements.txt
pip install flask flask-cors plotly pandas numpy

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker first."
    exit 1
fi

# Start Docker services
echo "Starting Docker services (Redis, Jaeger, Prometheus, Grafana)..."
docker-compose up -d

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 10

# Start the main scanner in the background
echo "Starting NIST compliance scanner..."
python3 scan.py &

# Start the dashboard application
echo "Starting web dashboard..."
python3 dashboard/app.py

# Note: When stopping, you'll need to:
# 1. Stop the Flask server (Ctrl+C)
# 2. Stop the background scanner process
# 3. Run 'docker-compose down' to stop Docker services
