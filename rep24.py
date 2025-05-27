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

    xticks = axs[0].get_xticks()
    axs[0].set_xticks(xticks[::max(1, len(xticks) // 10)])  # Show every 10th tick

    yticks = axs[0].get_yticks()
    axs[0].set_yticks(yticks[::max(1, len(yticks) // 10)])  # Show every 10th tick

    axs[0].set_title("srcIP vs dstIP")

    # Plot 2: srcIP vs dstPort
    axs[1].scatter(df["srcIP"], df["dstPort"], alpha=0.6)
    axs[1].set_xlabel("srcIP")
    axs[1].set_ylabel("dstPort")
    axs[1].tick_params(axis='x', rotation=45)

    xticks = axs[1].get_xticks()
    axs[1].set_xticks(xticks[::max(1, len(xticks) // 10)])  # Show every 10th tick

    yticks = axs[1].get_yticks()
    axs[1].set_yticks(yticks[::max(1, len(yticks) // 10)])  # Show every 10th tick

    axs[1].set_title("srcIP vs dstPort")

    # Plot 3: dstIP vs dstPort
    axs[2].scatter(df["dstIP"], df["dstPort"], alpha=0.6)
    axs[2].set_xlabel("dstIP")
    axs[2].set_ylabel("dstPort")
    axs[2].tick_params(axis='x', rotation=45)

    xticks = axs[2].get_xticks()
    axs[2].set_xticks(xticks[::max(1, len(xticks) // 10)])  # Show every 10th tick

    yticks = axs[2].get_yticks()
    axs[2].set_yticks(yticks[::max(1, len(yticks) // 10)])  # Show every 10th tick

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

        analyze_pcap(file["filename"], plot_prefix)
