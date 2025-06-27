#!/bin/bash
# Setup script for VPC Flow Log Investigator

set -e

echo "Setting up VPC Flow Log Investigator..."

# Check if Poetry is installed
if ! command -v poetry &> /dev/null; then
    echo "Poetry not found. Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
fi

# Install dependencies
echo "Installing dependencies..."
poetry install

echo "Setup complete!"
echo "Run 'poetry run vpc-flow-web' to start the web interface"
echo "Run 'poetry run vpc-flow-investigator --help' for CLI usage"