import pandas as pd
from collections import Counter

# Load your CSV file
df = pd.read_csv('workfiles/mawi_team29.csv')  # Replace with actual filename

# Inspect column names to find the Protocol column
print(df.columns)  # Run once to find the correct column name

print(df)

# Count protocol occurrences
top_protocols = df['protocolIdentifier'].value_counts().head(10)

# Map protocol names to numbers (expand as needed)

# Output result in desired format
for protocol, count in top_protocols.items():
    print(f"{protocol}: {count}")
