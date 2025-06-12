#!/bin/bash

# NetSec Lab Competition - Main Execution Script
# Usage: ./run.sh <pcap-file>

set -e  # Exit on any error

# Check if PCAP file is provided
if [ $# -eq 0 ]; then
    echo "Error: No PCAP file provided"
    echo "Usage: ./run.sh <pcap-file>"
    exit 1
fi

PCAP_FILE=$1

# Validate PCAP file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: PCAP file '$PCAP_FILE' not found"
    exit 1
fi

echo "=== NetSec Lab IDS - Advanced ML Solution ==="
echo "Processing: $PCAP_FILE"
echo "Start time: $(date)"

# Set up environment
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Run the prediction
python3 advanced_ids.py predict "$PCAP_FILE"

# Verify output file was created
if [ ! -f "output.csv" ]; then
    echo "Error: output.csv was not generated"
    exit 1
fi

echo "=== Processing Complete ==="
echo "End time: $(date)"
echo "Output saved to: output.csv"

# Display summary statistics
echo "=== Results Summary ==="
python3 -c "
import pandas as pd
df = pd.read_csv('output.csv')
print(f'Total flows processed: {len(df)}')
print(f'Normal flows: {len(df[df[\"Binary_Label\"] == 0])}')
print(f'Attack flows: {len(df[df[\"Binary_Label\"] == 1])}')
print('Attack types detected:')
attack_counts = df[df['Binary_Label'] == 1]['Attack_Type_enc'].value_counts()
for attack_type, count in attack_counts.items():
    print(f'  {attack_type}: {count}')
"
