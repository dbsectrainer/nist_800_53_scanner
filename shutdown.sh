#!/bin/bash

echo "Shutting down NIST 800-53 Compliance Scanner..."

# Kill Python processes
echo "Stopping Python processes..."
pkill -f "python3 scan.py"
pkill -f "python3 dashboard/app.py"

# Stop Docker services
echo "Stopping Docker services..."
docker-compose down

echo "Shutdown complete!"
echo "Note: if you activated venv in this shell (source venv/bin/activate), run 'deactivate' manually."
