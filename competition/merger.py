import pandas as pd

# Load the CSV files
df1 = pd.read_csv("train.csv")  # The one with flow data
df2 = pd.read_csv("flowkeys_training_labeled_enc.csv")  # The one with Binary_Label and Attack_Type_enc

# Define the common columns to merge on
merge_keys = [
    "flowStartMilliseconds",
    "sourceIPAddress",
    "destinationIPAddress",
    "sourceTransportPort",
    "destinationTransportPort"
]

# Merge the two DataFrames
merged_df = pd.merge(df1, df2, on=merge_keys, how='left')

# Save or display the result
merged_df.to_csv("merged_train.csv", index=False)
print(merged_df.head())
