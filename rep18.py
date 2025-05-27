import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

df = pd.read_csv("team29_monthly.csv", header=0)

df.columns = df.columns.str.strip()
df.columns = ["timestamp", "packets", "bytes", "uIPs", "uIPd"]

for col in ["packets", "bytes", "uIPs", "uIPd"]:
    df[col] = pd.to_numeric(df[col].astype(str).str.strip(), errors="coerce")

df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")

stats = {
    "total sum": df[["packets", "bytes", "uIPs", "uIPd"]].sum(),
    "mean": df[["packets", "bytes", "uIPs", "uIPd"]].mean(),
    "median": df[["packets", "bytes", "uIPs", "uIPd"]].median(),
    "std.dev": df[["packets", "bytes", "uIPs", "uIPd"]].std()
}

table = pd.DataFrame(stats)
table.index = ["#pkts/hour", "#bytes/hour", "#uIPs/hour", "#uIPd/hour"]

print("Table A:")
print(table.round(2))

start_time = df["timestamp"].min()
end_time = df["timestamp"].max()

df2 = pd.read_csv("global_last10years.csv", header=0)

df2.columns = df2.columns.str.strip()

df2.columns = ["timestamp", "bytes", "packets", "uIPs", "uIPd"]

for col in ["bytes", "packets", "uIPs", "uIPd"]:
    df2[col] = pd.to_numeric(df2[col].astype(str).str.strip(), errors="coerce")

df2["timestamp"] = pd.to_datetime(df2["timestamp"], unit="s")

df2_subset = df2[(df2["timestamp"] >= start_time) & (df2["timestamp"] <= end_time)]

df2_subset = df2_subset.dropna(subset=["bytes", "packets", "uIPs", "uIPd"])

stats = {
    "total sum": df2_subset[["packets", "bytes", "uIPs", "uIPd"]].sum(),
    "mean": df2_subset[["packets", "bytes", "uIPs", "uIPd"]].mean(),
    "median": df2_subset[["packets", "bytes", "uIPs", "uIPd"]].median(),
    "std.dev": df2_subset[["packets", "bytes", "uIPs", "uIPd"]].std()
}

table = pd.DataFrame(stats)
table.index = ["#pkts/hour", "#bytes/hour", "#uIPs/hour", "#uIPd/hour"]

print("Table B:")
print(table.round(2))

fig, axes = plt.subplots(nrows=2, ncols=4, figsize=(20, 10))

# Histograms
for i, col in enumerate(["packets", "bytes", "uIPs", "uIPd"]):
    sns.histplot(df[col], ax=axes[0, i])
    axes[0, i].set_title(f'Histogram of {col}')
    axes[0, i].set_xlabel('')
    axes[0, i].set_ylabel('')

for i, col in enumerate(["packets", "bytes", "uIPs", "uIPd"]):
    sns.histplot(df2_subset[col], ax=axes[1, i])
    axes[1, i].set_xlabel('')
    axes[1, i].set_ylabel('')

plt.tight_layout()
plt.show()

fig, axes = plt.subplots(nrows=2, ncols=4, figsize=(20, 10))

# Box plots
for i, col in enumerate(["packets", "bytes", "uIPs", "uIPd"]):
    sns.boxplot(y=df[col], ax=axes[0, i])
    axes[0, i].set_title(f'Box Plot of {col}')
    axes[0, i].set_xlabel('')
    axes[0, i].set_ylabel('')

for i, col in enumerate(["packets", "bytes", "uIPs", "uIPd"]):
    sns.boxplot(y=df2_subset[col], ax=axes[1, i])
    axes[1, i].set_xlabel('')
    axes[1, i].set_ylabel('')

plt.tight_layout()
plt.show()