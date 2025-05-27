import pandas as pd

import re

# Protocol number to name mapping (common IP protocols)
protocol_names = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
    132: "SCTP",
}


# Read the protocol CSV file
protocol_df = pd.read_csv("workfiles/team29_protocol.csv")

print(protocol_df.columns)

# Extract protocol numbers from column headers
protocol_numbers = []
for col in protocol_df.columns:
    match = re.match(r"(\d+)", col.strip())

    print(f"Processing column: {col}, Match: {match}")
    if match:
        protocol_numbers.append(int(match.group(1)))

# Get unique protocol numbers (should be the 3 main protocols)
unique_protocols = list(dict.fromkeys(protocol_numbers))[
    :3
]  # Keep order, take first 3

print(f"\nUnique protocols found: {unique_protocols}\n")


# Format the main protocols result for rep-19
protocol_strings = []
for num in unique_protocols:
    name = protocol_names.get(num, "Unknown")
    protocol_strings.append(f"{num}({name})")

main_protocols_result = " ".join(protocol_strings)

print(f"[rep-19] Main protocols: {main_protocols_result}\n")
