#!/bin/bash

# Check if argument was provided
if [ -z "$1" ]; then
  echo "Usage: ./run.sh <pcap-file>"
  exit 1
fi

PCAP_FILE="$1"

chmod +x go-flows
# 1. Run go-flows to extract features from the PCAP file
./go-flows run features 4tuple_bidi.json export csv train.csv source libpcap "$PCAP_FILE"

# 2. Run prediction script
python train_simple.py
