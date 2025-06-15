#!/bin/bash

# Check if argument was provided
if [ -z "$1" ]; then
  echo "Usage: ./run.sh <pcap-file>"
  exit 1
fi

PCAP_FILE="$1"

python -m pip install tqdm imblearn

chmod +x go-flows
# 1. Run go-flows to extract features from the PCAP file
./go-flows run features 4tuple_bidi.json export csv test.csv source libpcap "$PCAP_FILE"

# 2. Run prediction script
# python predict.py
python predict_enhanced.py -m enhanced_threat_detection_model.pkl -i test.csv -o output.csv
