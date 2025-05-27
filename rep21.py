import math as m

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def interpolate_nans(arr):
    arr = arr.copy()
    arr = pd.to_numeric(arr, errors='coerce')  # Convert to numeric, coercing errors to NaN
    nans = np.isnan(arr)
    if np.all(nans):
        return arr
    x = np.arange(arr.size)
    arr[nans] = np.interp(x[nans], x[~nans], arr[~nans])
    return arr

# Load dataset
dataset = pd.read_csv('workfiles/team29_protocol.csv')
pkts = interpolate_nans(dataset.iloc[:, 1].to_numpy())
uips = interpolate_nans(dataset.iloc[:, 2].to_numpy())

n = len(pkts)
k_vals = range(1, m.floor(n/2))

# --- Plot time series ---
plt.figure(figsize=(12, 6))
plt.subplot(2, 1, 1)
plt.plot(pkts)
plt.title('#pkts/hour')

plt.subplot(2, 1, 2)
plt.plot(uips)
plt.title('#uIPs/hour')
plt.tight_layout()
plt.savefig('output/team29_Ex3_month-TSs.png')
plt.close()

# --- FFT and Amplitudes ---
fft_pkts = np.fft.fft(pkts)
fft_uips = np.fft.fft(uips)

amp_pkts = np.abs(fft_pkts)
amp_uips = np.abs(fft_uips)

# Ignore k=0
y_pkts = amp_pkts[1:m.floor(n/2)]
y_uips = amp_uips[1:m.floor(n/2)]

# Find max peak
max_k_pkts = np.argmax(y_pkts) + 1
max_amp_pkts = y_pkts[max_k_pkts - 1]

max_k_uips = np.argmax(y_uips) + 1
max_amp_uips = y_uips[max_k_uips - 1]

# Period in hours
period_pkts = n / max_k_pkts
period_uips = n / max_k_uips

# --- Plot FFT ---
plt.figure(figsize=(12, 6))
plt.subplot(2, 1, 1)
plt.plot(k_vals, y_pkts)
plt.title('FFT Amplitude - #pkts/hour')

plt.subplot(2, 1, 2)
plt.plot(k_vals, y_uips)
plt.title('FFT Amplitude - #uIPs/hour')
plt.tight_layout()
plt.savefig('output/team29_Ex3_month-FFTs.png')
plt.close()

# --- Print Report Values ---
print(f"rep-21a: {max_amp_pkts/1e6:.2f}")
print(f"rep-21b: {max_k_pkts}")
print(f"rep-21c: {period_pkts:.1f}")
print(f"rep-21d: {max_amp_uips/1e6:.2f}")
print(f"rep-21e: {max_k_uips}")
print(f"rep-21f: {period_uips:.1f}")
