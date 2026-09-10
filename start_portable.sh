#!/bin/bash
# start_portable.sh - Log Analyzer Portable Launcher for Linux/Mac

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Check Python availability
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip and install dependencies
echo "Installing dependencies..."
python -m pip install --upgrade pip --quiet 2>/dev/null || true
python -m pip install flask werkzeug plotly watchdog reportlab --quiet 2>/dev/null

# Optional: Install optional dependencies
echo "Checking for optional dependencies..."
python -m pip install pywin32 --quiet 2>/dev/null || true

# Set up environment (will be replaced during package generation)
export ACTIVE_PLAYBOOK_TYPES="${ACTIVE_PLAYBOOK_TYPES:-all}"

# Display startup info
echo ""
echo "=========================================="
echo "Log Analyzer - Portable Edition"
echo "=========================================="
echo "Active Playbooks: $ACTIVE_PLAYBOOK_TYPES"
echo "Web UI: http://localhost:5000"
echo ""
echo "Starting application..."
echo "Press Ctrl+C to stop"
echo "=========================================="
echo ""

# Start the application
python run_portable.py
