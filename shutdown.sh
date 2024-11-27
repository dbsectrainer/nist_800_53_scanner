#!/bin/bash

echo "Shutting down NIST 800-53 Compliance Scanner..."

# Kill Python processes
echo "Stopping Python processes..."
pkill -f "python3 scan.py"
pkill -f "python3 dashboard/app.py"

# Stop Docker services
echo "Stopping Docker services..."
docker-compose down

# Deactivate virtual environment if it's active
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "Deactivating virtual environment..."
    deactivate
fi

echo "Shutdown complete!"
