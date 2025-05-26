# library imports
import matplotlib.dates as mdate
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import pearsonr


def interpolate_nans(arr):
    arr = arr.copy()
    nans = np.isnan(arr)
    if np.all(nans):
        return arr
    x = np.arange(arr.size)
    arr[nans] = np.interp(x[nans], x[~nans], arr[~nans])
    return arr


# loading data from CSV file
dataset = pd.read_csv("workfiles/global_last10years.csv")

# create a list with packets_per_day
ts_destination_ips = dataset["# Unique Destination IPs"]
ts_destination_ips = interpolate_nans(ts_destination_ips).tolist()
ts_destination_ips = [
    float(x) if str(x).strip() != "" else 0.0 for x in ts_destination_ips
]  # Convert to integers if necessary

ts_bytes = dataset[" # Bytes"].tolist()
ts_bytes = [float(x) if str(x).strip() != "" else 0.0 for x in ts_bytes]

ts_source_ips = dataset["# Unique Source IPs"]
ts_source_ips = interpolate_nans(ts_source_ips).tolist()
ts_source_ips = [
    float(x) if str(x).strip() != "" else 0.0 for x in ts_source_ips
]  # Convert to integers if necessary

ts_packets = dataset["# Packets"].tolist()
ts_packets = [float(x) if str(x).strip() != "" else 0.0 for x in ts_packets]

# Clean and convert ts_bytes

# Compute Pearson correlations
corr_a, _ = pearsonr(ts_packets, ts_destination_ips)
corr_b, _ = pearsonr(ts_packets, ts_bytes)
corr_c, _ = pearsonr(ts_source_ips, ts_destination_ips)

# Print results with two decimal places
print(f"rep-15a: {corr_a:.2f}")
print(f"rep-15b: {corr_b:.2f}")
print(f"rep-15c: {corr_c:.2f}")
