import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# CSV einlesen
df = pd.read_csv("team29_monthly.csv", header=0)

# Spalten bereinigen
df.columns = df.columns.str.strip()

# Spalten umbenennen für Klarheit
df.columns = ["timestamp", "packets", "bytes", "uIPs", "uIPd"]

for col in ["packets", "bytes", "uIPs", "uIPd"]:
    df[col] = pd.to_numeric(df[col].astype(str).str.strip(), errors="coerce")

# Unix-Timestamps in Datum (optional)
df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")

# Statistiken berechnen
stats = {
    "total sum": df[["packets", "bytes", "uIPs", "uIPd"]].sum(),
    "mean": df[["packets", "bytes", "uIPs", "uIPd"]].mean(),
    "median": df[["packets", "bytes", "uIPs", "uIPd"]].median(),
    "standard deviation": df[["packets", "bytes", "uIPs", "uIPd"]].std()
}

# In Tabelle (DataFrame) umwandeln und Zeilen sortieren
table_a = pd.DataFrame(stats)
table_a.index = ["#pkts/hour", "#bytes/hour", "#uIPs/hour", "#uIPd/hour"]

# Ausgabe
print("Table A – Basic Statistics:")
print(table_a.round(2))

