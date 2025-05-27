import pandas as pd

# Load data
dataset = pd.read_csv('workfiles/global_last10years.csv')

# Convert timestamps to datetime in UTC (UNIX timestamps are usually in UTC)
dataset['datetime'] = pd.to_datetime(dataset['timestamp'], unit='s', utc=True)

# Convert IP counts to numeric, fill invalid entries with 0
dataset['# Unique Source IPs'] = pd.to_numeric(dataset['# Unique Source IPs'], errors='coerce').fillna(0)

# Find the row with the max value
max_row = dataset.loc[dataset['# Unique Source IPs'].idxmax()]

# Format the datetime
max_datetime = max_row['datetime']
formatted = max_datetime.strftime('%#d-%#m-%Y %H')

print(f'Main peak: {formatted}')
