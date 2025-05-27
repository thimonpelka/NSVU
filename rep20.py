import re

import pandas as pd


def analyze_protocols():
    try:
        # Read the protocol CSV file
        protocol_df = pd.read_csv("workfiles/team29_protocol.csv")

        # Read the monthly CSV file for totals
        monthly_df = pd.read_csv("workfiles/team29_monthly.csv")

        # Calculate totals from monthly data
        total_pkts = monthly_df["#packets"].sum()
        total_uips = monthly_df["#unique_IP_sources"].sum()
        total_uipd = monthly_df["#unique_IP_destinations"].sum()

        # Calculate totals from the three main protocols
        main_pkts = 0
        main_uips = 0
        main_uipd = 0

        for col in protocol_df.columns:
            if "Packets" in col:
                main_pkts += pd.to_numeric(protocol_df[col],
                                           errors="coerce").sum()
            elif "Source" in col:
                main_uips += pd.to_numeric(protocol_df[col],
                                           errors="coerce").sum()
            elif "Destination" in col:
                main_uipd += pd.to_numeric(protocol_df[col],
                                           errors="coerce").sum()

        # Calculate percentages for "others" (residual)
        others_pkts_pct = (total_pkts - main_pkts) / total_pkts * 100
        others_uips_pct = (total_uips - main_uips) / total_uips * 100
        others_uipd_pct = (total_uipd - main_uipd) / total_uipd * 100

        # Print results with proper formatting
        print(f"rep-20a: {others_pkts_pct:.2f}%")
        print(f"rep-20b: {others_uips_pct:.2f}%")
        print(f"rep-20c: {others_uipd_pct:.2f}%")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    analyze_protocols()
