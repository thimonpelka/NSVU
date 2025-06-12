#!/bin/bash

# Setup script for NetSec Lab Competition
# Run this to prepare the evaluation environment

echo "=== NetSec Lab Competition Setup ==="

# Update package manager
echo "Updating system packages..."
sudo apt update

# Install Python dependencies
echo "Installing Python packages..."
pip3 install --user -r requirements.txt

# Install Go (if not already installed)
if ! command -v go &> /dev/null; then
    echo "Installing Go..."
    wget https://golang.org/dl/go1.19.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi

# Install Go-Flows
echo "Installing Go-Flows..."
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
go install github.com/CN-TU/go-flows/cmd/go-flows@latest

# Make scripts executable
chmod +x run.sh
chmod +x advanced_ids.py
chmod +x train_model.py

# Verify installation
echo "=== Verification ==="
echo "Python version: $(python3 --version)"
echo "Go version: $(go version 2>/dev/null || echo 'Go not found')"
echo "Go-Flows installed: $(which go-flows 2>/dev/null || echo 'Not found - check GOPATH')"

# Test Python imports
echo "Testing Python dependencies..."
python3 -c "
import pandas as pd
import numpy as np
import sklearn
import xgboost as xgb
print('✓ All Python dependencies working')
" || echo "✗ Python dependency issues - check requirements.txt"

echo ""
echo "=== Setup Complete ==="
echo "Next steps:"
echo "1. Place your training data files in this directory:"
echo "   - training_clean_mod.pcap"
echo "   - flowkeys_training_labeled_enc.csv"
echo "   - 4tuple_bidi.json"
echo ""
echo "2. Train your model:"
echo "   python3 train_model.py"
echo ""
echo "3. Test with competition data:"
echo "   ./run.sh test.pcap"
echo ""
