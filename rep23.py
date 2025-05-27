import pandas as pd

df = pd.read_csv("workfiles/Ex2flows_team_29.csv", header=0)

print(df.columns)

# Focus on the TCP flags mode column
tcp_flags_col = df["mode(_tcpFlags)"].dropna()

# Count frequencies
tcp_flag_counts = tcp_flags_col.value_counts()

# Calculate total for percentage
total = tcp_flag_counts.sum()

# Get top 3 with percentages
top_3 = tcp_flag_counts.head(3)

# Print results formatted
for i, (flag, count) in enumerate(top_3.items()):
    percent = (count / total) * 100
    label = chr(ord('a') + i * 2)  # 'a', 'c', 'e'
    print(f"rep-23{label}: {flag}")
    print(f"rep-23{chr(ord(label)+1)}: {percent:.1f}%")
