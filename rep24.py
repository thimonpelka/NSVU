import sys
from collections import Counter

import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import ICMP, IP, TCP, UDP, rdpcap

def scatter_combined(df, plot_prefix):
    fig, axs = plt.subplots(1, 3, figsize=(18, 6))  # 1 row, 3 columns

    # Plot 1: srcIP vs dstIP
    axs[0].scatter(df["srcIP"], df["dstIP"], alpha=0.6)
    axs[0].set_xlabel("srcIP")
    axs[0].set_ylabel("dstIP")
    axs[0].tick_params(axis='x', rotation=45)
    axs[0].set_title("srcIP vs dstIP")

    # Plot 2: srcIP vs dstPort
    axs[1].scatter(df["srcIP"], df["dstPort"], alpha=0.6)
    axs[1].set_xlabel("srcIP")
    axs[1].set_ylabel("dstPort")
    axs[1].tick_params(axis='x', rotation=45)
    axs[1].set_title("srcIP vs dstPort")

    # Plot 3: dstIP vs dstPort
    axs[2].scatter(df["dstIP"], df["dstPort"], alpha=0.6)
    axs[2].set_xlabel("dstIP")
    axs[2].set_ylabel("dstPort")
    axs[2].tick_params(axis='x', rotation=45)
    axs[2].set_title("dstIP vs dstPort")

    plt.tight_layout()
    plt.savefig(f"output/team29_Ex4_{plot_prefix}_scatter.png")
    plt.close()

def analyze_pcap(filename, plot_prefix):
    packets = rdpcap(filename)
    data = []

    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = (
                pkt[TCP].dport
                if TCP in pkt
                else (pkt[UDP].dport if UDP in pkt else None)
            )
            proto = (
                "TCP"
                if TCP in pkt
                else ("UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "Other")
            )
            data.append((src, dst, dport, proto))

    df = pd.DataFrame(data, columns=["srcIP", "dstIP", "dstPort", "proto"])

    # Scatter plots
    scatter_combined(df, plot_prefix)

    # Analysis
    src_counts = df["srcIP"].value_counts()
    dst_counts = df["dstIP"].value_counts()
    dst_port_counts = df["dstPort"].value_counts()

    unique_src = df["srcIP"].nunique()
    unique_dst = df["dstIP"].nunique()
    unique_ports = df["dstPort"].nunique()

    suspected_attacker = src_counts.idxmax()
    top_dst = dst_counts.idxmax()

    result = {}

    if "ICMP" in df["proto"].values:
        result["type"] = "ping flood attack"
    elif unique_dst > 10 and unique_ports <= 5:
        result["type"] = "horizontal scan"
    elif unique_dst <= 5 and unique_ports > 10:
        result["type"] = "vertical scan"
    elif unique_src > 10 and dst_counts.max() > 100:
        result["type"] = "DDoS attack"
    elif dst_port_counts.max() > 20:
        result["type"] = "brute force attack"
    else:
        result["type"] = "unknown"

    result["attacker"] = (
        suspected_attacker if result["type"] != "DDoS attack" else "multiple"
    )
    result["target"] = top_dst
    result["port"] = (
        df[df["dstIP"] == top_dst]["dstPort"].mode().values[0]
        if not df[df["dstIP"] == top_dst]["dstPort"].isnull().all()
        else "N/A"
    )
    result["num_targets_or_ports"] = (
        unique_ports
        if result["type"] in ["vertical scan", "brute force attack"]
        else unique_dst
    )
    result["found_vulnerable"] = "yes" if dst_port_counts.max() > 10 else "no"
    result["num_vulnerable"] = sum(dst_port_counts > 10)
    result["ddos_ack"] = (
        "not applicable" if result["type"] != "DDoS attack" else dst_counts.max(
        )
    )

    return result


if __name__ == "__main__":

    files = [
        {
            "prefix": "A",
            "filename": "workfiles/team29_A.pcap",
        },
        {
            "prefix": "B",
            "filename": "workfiles/team29_B.pcap",
        },
        {
            "prefix": "C",
            "filename": "workfiles/team29_C.pcap",
        },
    ]

    for file in files:
        plot_prefix = file["prefix"]

        result = analyze_pcap(file["filename"], plot_prefix)

        print(f"{plot_prefix}-a: {result['type']}")
        print(f"{plot_prefix}-b: {result['attacker']}")
        print(f"{plot_prefix}-c: {result['target']}")
        print(f"{plot_prefix}-d: {result['port']}")
        print(f"{plot_prefix}-e: {result['num_targets_or_ports']}")
        print(f"{plot_prefix}-f: {result['found_vulnerable']}")
        print(f"{plot_prefix}-g: {result['num_vulnerable']}")
        print(f"{plot_prefix}-h: {result['ddos_ack']}\n")
